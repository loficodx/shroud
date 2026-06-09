use anyhow::{Context, Result};
use shroud_core::import::{decode_import_connection, render_client_yaml_from_import};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportedClientConfig {
    pub yaml: String,
    pub default_file_name: String,
}

pub fn render_imported_client_yaml(raw: &str) -> Result<ImportedClientConfig> {
    let conn = decode_import_connection(raw).context("failed to decode import string")?;
    let file_name_source = conn
        .name
        .as_deref()
        .filter(|name| !name.trim().is_empty())
        .unwrap_or(&conn.server);
    let default_file_name = default_import_file_name(Some(file_name_source));
    let yaml = render_client_yaml_from_import(conn).context("failed to render client config")?;

    Ok(ImportedClientConfig {
        yaml,
        default_file_name,
    })
}

pub fn default_import_file_name(name: Option<&str>) -> String {
    format!(
        "client-{}.yaml",
        sanitize_profile_name(name.unwrap_or("import"))
    )
}

fn sanitize_profile_name(name: &str) -> String {
    let mut out = String::new();
    let mut last_dash = false;

    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if (ch == '-' || ch == '_') && !out.is_empty() {
            out.push(ch);
            last_dash = false;
        } else if !last_dash && !out.is_empty() {
            out.push('-');
            last_dash = true;
        }
    }

    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        "import".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn unique_import_file_path(base_path: &Path) -> PathBuf {
    if !base_path.exists() {
        return base_path.to_path_buf();
    }

    let parent = base_path.parent();
    let stem = base_path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .filter(|stem| !stem.is_empty())
        .unwrap_or("client-import");
    let extension = base_path
        .extension()
        .and_then(|extension| extension.to_str());

    for suffix in 1.. {
        let file_name = match extension {
            Some(extension) if !extension.is_empty() => format!("{stem}-{suffix}.{extension}"),
            _ => format!("{stem}-{suffix}"),
        };
        let candidate = parent
            .map(|parent| parent.join(&file_name))
            .unwrap_or_else(|| PathBuf::from(&file_name));
        if !candidate.exists() {
            return candidate;
        }
    }

    unreachable!("unbounded suffix search must eventually find a free import file path")
}

#[cfg(test)]
mod tests {
    use super::{default_import_file_name, render_imported_client_yaml, unique_import_file_path};
    use shroud_core::config::TransportMode;
    use shroud_core::import::{ImportConnection, encode_import_connection};
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn default_import_file_name_uses_sanitized_profile_name() {
        assert_eq!(
            default_import_file_name(Some("Work Laptop")),
            "client-work-laptop.yaml"
        );
        assert_eq!(default_import_file_name(Some("!!!")), "client-import.yaml");
    }

    #[test]
    fn render_imported_client_yaml_uses_server_for_default_file_name_when_name_is_missing() {
        let raw = encode_import_connection(&ImportConnection {
            name: None,
            server: "138.124.55.220".to_string(),
            port: 8443,
            mode: TransportMode::RawTcp,
            tls: true,
            tls_server_name: Some("138.124.55.220".to_string()),
            tls_server_cert_sha256:
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            client_id: "c1ce8312-7c35-4e70-867a-3af4ac7f68d7".to_string(),
            client_secret: "secret".to_string(),
        })
        .expect("encode import");

        let imported = render_imported_client_yaml(&raw).expect("render imported client yaml");

        assert_eq!(imported.default_file_name, "client-138-124-55-220.yaml");
        assert!(imported.yaml.contains("server: 138.124.55.220\n"));
    }

    #[test]
    fn unique_import_file_path_adds_numeric_suffix_when_file_exists() {
        let dir = std::env::temp_dir().join(format!(
            "shroud-gui-import-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after unix epoch")
                .as_nanos()
        ));
        fs::create_dir_all(&dir).expect("create temp dir");
        fs::write(dir.join("client-laptop.yaml"), "").expect("write base file");
        fs::write(dir.join("client-laptop-1.yaml"), "").expect("write suffixed file");

        assert_eq!(
            unique_import_file_path(&dir.join("client-laptop.yaml")),
            dir.join("client-laptop-2.yaml")
        );

        let _ = fs::remove_dir_all(dir);
    }
}
