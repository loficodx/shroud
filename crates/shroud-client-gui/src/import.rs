use anyhow::{Context, Result};
use shroud_core::import::{decode_import_connection, render_client_yaml_from_import};

pub fn render_imported_client_yaml(raw: &str) -> Result<(String, Option<String>)> {
    let conn = decode_import_connection(raw).context("failed to decode import string")?;
    let name = conn.name.clone();
    let yaml = render_client_yaml_from_import(conn).context("failed to render client config")?;

    Ok((yaml, name))
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

#[cfg(test)]
mod tests {
    use super::default_import_file_name;

    #[test]
    fn default_import_file_name_uses_sanitized_profile_name() {
        assert_eq!(
            default_import_file_name(Some("Work Laptop")),
            "client-work-laptop.yaml"
        );
        assert_eq!(default_import_file_name(Some("!!!")), "client-import.yaml");
    }
}
