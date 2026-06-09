use anyhow::{Context, Result};
use glob::glob;
use shroud_core::config::load_client_config_yaml;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ClientConfigFile {
    pub path: PathBuf,
    pub display_name: String,
    pub raw_yaml: String,
    pub is_valid: bool,
    pub error: Option<String>,
}

impl ClientConfigFile {
    fn from_path(path: PathBuf) -> Self {
        let display_name = path.display().to_string();
        let (raw_yaml, is_valid, error) = match fs::read_to_string(&path) {
            Ok(raw_yaml) => match load_client_config_yaml(&raw_yaml) {
                Ok(_) => (raw_yaml, true, None),
                Err(err) => (raw_yaml, false, Some(err.to_string())),
            },
            Err(err) => (
                String::new(),
                false,
                Some(format!(
                    "failed to read client config {}: {err}",
                    path.display()
                )),
            ),
        };

        Self {
            path,
            display_name,
            raw_yaml,
            is_valid,
            error,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConfigStore {
    search_patterns: Vec<String>,
}

impl Default for ConfigStore {
    fn default() -> Self {
        Self {
            search_patterns: vec![
                "client*.yaml".to_string(),
                "configs/client*.yaml".to_string(),
            ],
        }
    }
}

impl ConfigStore {
    pub fn discover(&self) -> Result<Vec<ClientConfigFile>> {
        let mut paths = Vec::new();
        let mut seen = HashSet::new();

        for pattern in &self.search_patterns {
            for entry in
                glob(pattern).with_context(|| format!("invalid glob pattern: {pattern}"))?
            {
                let path =
                    entry.with_context(|| format!("failed to read glob entry: {pattern}"))?;
                if !path.is_file() {
                    continue;
                }

                let dedupe_path = fs::canonicalize(&path).unwrap_or_else(|_| path.clone());
                if seen.insert(dedupe_path) {
                    paths.push(path);
                }
            }
        }

        paths.sort_by(|left, right| {
            left.file_name()
                .cmp(&right.file_name())
                .then_with(|| left.cmp(right))
        });
        Ok(paths.into_iter().map(ClientConfigFile::from_path).collect())
    }

    pub fn save(&self, path: &Path, raw: &str) -> Result<()> {
        self.validate(raw)?;
        let tmp_path = atomic_save_tmp_path(path);
        fs::write(&tmp_path, raw).with_context(|| {
            format!(
                "failed to write temporary client config: {}",
                tmp_path.display()
            )
        })?;
        fs::rename(&tmp_path, path).with_context(|| {
            let _ = fs::remove_file(&tmp_path);
            format!("failed to save client config: {}", path.display())
        })
    }

    pub fn validate(&self, raw: &str) -> Result<()> {
        load_client_config_yaml(raw).map(|_| ()).map_err(Into::into)
    }
}

fn atomic_save_tmp_path(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_else(|| "client.yaml".into());
    path.with_file_name(format!("{file_name}.tmp"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after unix epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "shroud-client-gui-config-store-{}-{unique}",
                std::process::id()
            ));
            fs::create_dir_all(&path).expect("create temp test dir");
            Self(path)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn valid_client_yaml() -> &'static str {
        include_str!("../../../configs/client.yaml")
    }

    #[test]
    fn save_validates_then_replaces_file_via_temp_file() {
        let dir = TestDir::new();
        let path = dir.path().join("client.yaml");
        let tmp_path = dir.path().join("client.yaml.tmp");
        fs::write(&path, "not valid yaml: [").expect("write original config");

        let store = ConfigStore {
            search_patterns: Vec::new(),
        };

        store.save(&path, valid_client_yaml()).expect("save config");

        assert_eq!(
            fs::read_to_string(&path).expect("read saved config"),
            valid_client_yaml()
        );
        assert!(!tmp_path.exists());
    }

    #[test]
    fn save_keeps_existing_file_when_validation_fails() {
        let dir = TestDir::new();
        let path = dir.path().join("client.yaml");
        fs::write(&path, valid_client_yaml()).expect("write original config");

        let store = ConfigStore {
            search_patterns: Vec::new(),
        };

        let err = store
            .save(&path, "transport: [")
            .expect_err("invalid config should fail");

        assert!(err.to_string().contains("yaml"));
        assert_eq!(
            fs::read_to_string(&path).expect("read original config"),
            valid_client_yaml()
        );
    }

    #[test]
    fn discover_reads_validates_and_sorts_client_configs() {
        let dir = TestDir::new();
        let configs_dir = dir.path().join("configs");
        fs::create_dir_all(&configs_dir).expect("create configs dir");
        fs::write(dir.path().join("client-z.yaml"), valid_client_yaml()).expect("write client-z");
        fs::write(dir.path().join("client-a.yaml"), "transport: [").expect("write client-a");
        fs::write(configs_dir.join("client-b.yaml"), valid_client_yaml()).expect("write client-b");

        let store = ConfigStore {
            search_patterns: vec![
                format!("{}/client*.yaml", dir.path().display()),
                format!("{}/configs/client*.yaml", dir.path().display()),
            ],
        };

        let configs = store.discover().expect("discover configs");
        let file_names = configs
            .iter()
            .map(|config| {
                config
                    .path
                    .file_name()
                    .expect("file name")
                    .to_string_lossy()
                    .into_owned()
            })
            .collect::<Vec<_>>();

        assert_eq!(
            file_names,
            ["client-a.yaml", "client-b.yaml", "client-z.yaml"]
        );
        assert!(!configs[0].is_valid);
        assert!(
            configs[0]
                .error
                .as_deref()
                .is_some_and(|err| err.contains("yaml"))
        );
        assert_eq!(configs[0].raw_yaml, "transport: [");
        assert!(configs[1].is_valid);
        assert!(configs[1].error.is_none());
        assert!(configs[1].raw_yaml.contains("transport:"));
    }

    #[test]
    fn discover_deduplicates_overlapping_patterns() {
        let dir = TestDir::new();
        let path = dir.path().join("client.yaml");
        fs::write(&path, valid_client_yaml()).expect("write client config");

        let store = ConfigStore {
            search_patterns: vec![
                path.display().to_string(),
                format!("{}/client*.yaml", dir.path().display()),
            ],
        };

        let configs = store.discover().expect("discover configs");

        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].path, path);
        assert!(configs[0].is_valid);
    }
}
