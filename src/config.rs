use anyhow::{Result, bail};
use serde::Deserialize;
use std::{collections::HashSet, path::PathBuf};

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub listen: String,
    pub interval_seconds: u64,
    pub timeout_seconds: u64,
    pub max_output_bytes: usize,
    pub max_entries: usize,
    pub export_filesystem: bool,
    pub include_names: Vec<String>,
    pub collectors: Vec<Collector>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Collector {
    pub id: String,
    pub kind: Kind,
    pub path: PathBuf,
    #[serde(default = "default_depth")]
    pub max_depth: usize,
}
fn default_depth() -> usize {
    4
}

#[derive(Clone, Copy, Debug, Deserialize, serde::Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Dpkg,
    Rpm,
    Pacman,
    Apk,
    Snap,
    Flatpak,
    Python,
    Npm,
    Cargo,
    Filesystem,
}
impl Kind {
    pub fn name(self) -> &'static str {
        match self {
            Self::Dpkg => "dpkg",
            Self::Rpm => "rpm",
            Self::Pacman => "pacman",
            Self::Apk => "apk",
            Self::Snap => "snap",
            Self::Flatpak => "flatpak",
            Self::Python => "python",
            Self::Npm => "npm",
            Self::Cargo => "cargo",
            Self::Filesystem => "filesystem",
        }
    }
    pub fn command(self) -> bool {
        matches!(
            self,
            Self::Dpkg | Self::Rpm | Self::Pacman | Self::Snap | Self::Flatpak
        )
    }
}
impl Default for Config {
    fn default() -> Self {
        let mut collectors = Vec::new();
        for (kind, path) in [
            (Kind::Dpkg, "/usr/bin/dpkg-query"),
            (Kind::Rpm, "/usr/bin/rpm"),
            (Kind::Pacman, "/usr/bin/pacman"),
            (Kind::Apk, "/lib/apk/db/installed"),
            (Kind::Snap, "/usr/bin/snap"),
            (Kind::Flatpak, "/usr/bin/flatpak"),
            (Kind::Filesystem, "/usr/local/bin"),
            (Kind::Filesystem, "/opt"),
        ] {
            if std::path::Path::new(path).exists() {
                collectors.push(Collector {
                    id: format!(
                        "{}-{}",
                        kind.name(),
                        path.trim_start_matches('/').replace('/', "-")
                    ),
                    kind,
                    path: path.into(),
                    max_depth: 4,
                });
            }
        }
        Self {
            listen: "127.0.0.1:9898".into(),
            interval_seconds: 900,
            timeout_seconds: 30,
            max_output_bytes: 16 * 1024 * 1024,
            max_entries: 100_000,
            export_filesystem: false,
            include_names: Vec::new(),
            collectors,
        }
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.interval_seconds == 0
            || self.timeout_seconds == 0
            || self.max_output_bytes == 0
            || self.max_entries == 0
        {
            bail!("interval, timeout and limits must be positive");
        }
        if self.max_output_bytes > 256 * 1024 * 1024 || self.max_entries > 1_000_000 {
            bail!("limits exceed maximum: 256 MiB output, 1,000,000 entries");
        }
        let mut ids = HashSet::new();
        for c in &self.collectors {
            if c.id.is_empty()
                || !c
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                || !ids.insert(&c.id)
            {
                bail!("collector IDs must be unique and contain only letters, numbers, '_' or '-'");
            }
            if !c.path.is_absolute() || c.max_depth == 0 || c.max_depth > 64 {
                bail!("{}: use an absolute path and depth 1..64", c.id);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn config_rejects_invalid_limits_paths_and_duplicates() {
        let mut config = Config {
            interval_seconds: 0,
            ..Config::default()
        };
        assert!(config.validate().is_err());
        config.interval_seconds = 1;
        config.collectors = vec![Collector {
            id: "one".into(),
            kind: Kind::Filesystem,
            path: "relative".into(),
            max_depth: 1,
        }];
        assert!(config.validate().is_err());
        config.collectors[0].path = "/opt".into();
        assert!(config.validate().is_ok());
        config.collectors.push(config.collectors[0].clone());
        assert!(config.validate().is_err());
        assert!(toml::from_str::<Config>("unknown_option = true").is_err());
    }
    #[test]
    fn example_config_is_valid() {
        let config: Config = toml::from_str(include_str!("../examples/config.toml")).unwrap();
        config.validate().unwrap();
        assert_eq!(config.collectors.len(), 3);
        assert!(
            toml::from_str::<Config>("collectors = []")
                .unwrap()
                .collectors
                .is_empty()
        );
    }
}
