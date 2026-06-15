use anyhow::{Context, Result};
use shroud_core::config::{ClientConfig, load_client_config_yaml};
use std::fs;
use std::path::Path;

pub fn load_client_config(path: &Path) -> Result<ClientConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("failed to read client config: {}", path.display()))?;

    load_client_config_yaml(&raw)
        .with_context(|| format!("failed to load client config: {}", path.display()))
}
