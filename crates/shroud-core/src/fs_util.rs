use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

pub fn create_parent_dir(path: &Path) -> Result<()> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create directory {}", parent.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::create_parent_dir;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn create_parent_dir_creates_missing_parent_directories() {
        let dir = unique_temp_dir();
        let file_path = dir.join("nested").join("client.yaml");

        create_parent_dir(&file_path).expect("create parent directory");

        assert!(dir.join("nested").is_dir());

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn create_parent_dir_allows_paths_without_parent_directory() {
        create_parent_dir(PathBuf::from("client.yaml").as_path()).expect("no parent directory");
    }

    fn unique_temp_dir() -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "shroud-core-fs-util-test-{}-{now}",
            std::process::id()
        ))
    }
}
