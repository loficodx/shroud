use anyhow::{Context, Result};
use glob::glob;
use shroud_core::config::load_client_config_yaml;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ClientConfigFile {
    pub path: PathBuf,
    pub label: String,
}

impl ClientConfigFile {
    fn from_path(path: PathBuf) -> Self {
        let label = path.display().to_string();
        Self { path, label }
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

        for pattern in &self.search_patterns {
            for entry in
                glob(pattern).with_context(|| format!("invalid glob pattern: {pattern}"))?
            {
                let path =
                    entry.with_context(|| format!("failed to read glob entry: {pattern}"))?;
                if path.is_file() && !paths.iter().any(|existing: &PathBuf| existing == &path) {
                    paths.push(path);
                }
            }
        }

        paths.sort();
        Ok(paths.into_iter().map(ClientConfigFile::from_path).collect())
    }

    pub fn read_to_string(&self, path: &Path) -> Result<String> {
        fs::read_to_string(path)
            .with_context(|| format!("failed to read client config: {}", path.display()))
    }

    pub fn save(&self, path: &Path, raw: &str) -> Result<()> {
        self.validate(raw)?;
        fs::write(path, raw)
            .with_context(|| format!("failed to save client config: {}", path.display()))
    }

    pub fn validate(&self, raw: &str) -> Result<()> {
        load_client_config_yaml(raw).map(|_| ()).map_err(Into::into)
    }
}
