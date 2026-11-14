use crate::{
    command,
    config::{Collector, Config, Kind},
    model::Software,
};
use anyhow::{Context, Result, bail};
use std::{
    collections::HashSet,
    fs::{self, File},
    io::Read,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use walkdir::WalkDir;

pub async fn collect(c: &Collector, config: &Config) -> Result<Vec<Software>> {
    if c.kind.command() {
        let args: &[&str] = match c.kind {
            Kind::Dpkg => &[
                "-W",
                "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\t${source:Package}\t${source:Version}\n",
            ],
            Kind::Rpm => &[
                "-qa",
                "--qf",
                "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n",
            ],
            Kind::Pacman => &["-Q"],
            Kind::Snap => &["list"],
            Kind::Flatpak => &[
                "list",
                "--columns=application,version,arch,branch,installation",
            ],
            _ => unreachable!(),
        };
        let output: String = command::run(
            &c.path,
            args,
            Duration::from_secs(config.timeout_seconds),
            config.max_output_bytes,
        )
        .await?;
        let items: Vec<Software> = parse_command(c, &output)?;
        if items.len() > config.max_entries {
            bail!("inventory exceeded entry limit");
        }
        Ok(items)
    } else {
        let c: Collector = c.clone();
        let config: Config = config.clone();
        let limit: usize = config.max_entries;
        let items: Vec<Software> = tokio::task::spawn_blocking(move || -> Result<Vec<Software>> {
            collect_files(&c, &config)
        })
        .await??;
        if items.len() > limit {
            bail!("inventory exceeded entry limit");
        }
        // Reject unrepresentable filesystem paths at the collector boundary so one
        // bad filename cannot prevent publication of the entire inventory cache.
        serde_json::to_vec(&items).context("collector contains a path that is not valid UTF-8")?;
        Ok(items)
    }
}

pub fn parse_command(c: &Collector, output: &str) -> Result<Vec<Software>> {
    let mut items: Vec<Software> = Vec::new();
    for (line_number, line) in output.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let item: Software = match c.kind {
            Kind::Dpkg => {
                let fields: Vec<&str> = line.split('\t').collect::<Vec<&str>>();
                if fields.len() != 6 {
                    bail!("invalid dpkg record at line {}", line_number + 1);
                }
                if fields[3] != "installed" {
                    continue;
                }
                Software::new(
                    c,
                    fields[0],
                    fields[1],
                    fields[2],
                    None,
                    "package database",
                    "",
                )
                .with_source(fields[4], fields[5])
            }
            Kind::Rpm => {
                let fields: Vec<&str> = line.split('\t').collect::<Vec<&str>>();
                if fields.len() != 4 {
                    bail!("invalid rpm record");
                }
                Software::new(
                    c,
                    fields[0],
                    fields[1],
                    fields[2],
                    None,
                    "package database",
                    "",
                )
                .with_source(source_rpm_name(fields[3]).unwrap_or(""), "")
            }
            Kind::Pacman => {
                let fields: Vec<&str> = line.split_whitespace().collect::<Vec<&str>>();
                if fields.len() != 2 {
                    bail!("invalid pacman record");
                }
                Software::new(c, fields[0], fields[1], "", None, "package database", "")
            }
            Kind::Snap => {
                if line_number == 0 && line.starts_with("Name ") {
                    continue;
                }
                if line.trim() == "No snaps are installed yet. Try 'snap install hello-world'." {
                    continue;
                }
                let fields: Vec<&str> = line.split_whitespace().collect::<Vec<&str>>();
                if fields.len() < 6 {
                    bail!("invalid snap record");
                }
                Software::new(
                    c,
                    fields[0],
                    fields[1],
                    "",
                    None,
                    &format!("snap list; revision {}", fields[2]),
                    "",
                )
            }
            Kind::Flatpak => {
                let fields: Vec<&str> = line.split('\t').collect::<Vec<&str>>();
                if fields.len() != 5 {
                    bail!("invalid flatpak record: expected five tab-separated columns");
                }
                let identity: String = format!("{}:{}", fields[4], fields[3]);
                Software::new(
                    c,
                    fields[0],
                    fields[1],
                    fields[2],
                    None,
                    &format!(
                        "flatpak list; installation {}; branch {}",
                        fields[4], fields[3]
                    ),
                    &identity,
                )
            }
            _ => bail!("not a command collector"),
        };
        if item.name.is_empty() || (item.version.is_none() && c.kind != Kind::Flatpak) {
            bail!("empty name or version in package record");
        }
        items.push(item);
    }
    Ok(items)
}

// O_NONBLOCK prevents a metadata path replaced by a FIFO from hanging open().
// Read limits and regular-file checks apply even to symlink targets.
/// Name part of a source RPM file name such as `openssl-3-3.0.8-150500.5.8.1.src.rpm`.
fn source_rpm_name(file: &str) -> Option<&str> {
    let stem: &str = file
        .strip_suffix(".src.rpm")
        .or_else(|| file.strip_suffix(".nosrc.rpm"))?;
    let (rest, _release): (&str, &str) = stem.rsplit_once('-')?;
    let (name, _version): (&str, &str) = rest.rsplit_once('-')?;
    (!name.is_empty()).then_some(name)
}

fn read_file(path: &Path, limit: usize) -> Result<String> {
    let file: File = File::options()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("open {}", path.display()))?;
    if !file.metadata()?.is_file() {
        bail!("not a regular file: {}", path.display());
    }
    let mut bytes: Vec<u8> = Vec::new();
    file.take(limit as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bail!("metadata file exceeded size limit: {}", path.display());
    }
    String::from_utf8(bytes).context("metadata is not UTF-8")
}
struct Budget {
    deadline: Instant,
    remaining: usize,
    bytes: usize,
}
impl Budget {
    fn tick(&mut self) -> Result<()> {
        if Instant::now() >= self.deadline {
            bail!("filesystem scan timed out");
        }
        if self.remaining == 0 {
            bail!("filesystem scan exceeded entry limit");
        }
        self.remaining -= 1;
        Ok(())
    }
    fn read(&mut self, path: &Path) -> Result<String> {
        self.tick()?;
        let text: String = read_file(path, self.bytes)?;
        self.bytes -= text.len();
        Ok(text)
    }
}
fn collect_files(c: &Collector, config: &Config) -> Result<Vec<Software>> {
    let mut budget: Budget = Budget {
        deadline: Instant::now() + Duration::from_secs(config.timeout_seconds),
        remaining: config.max_entries,
        bytes: config.max_output_bytes,
    };
    match c.kind {
        Kind::Apk => parse_apk(c, &budget.read(&c.path)?),
        Kind::Cargo => parse_cargo(c, &budget.read(&c.path.join(".crates.toml"))?),
        Kind::Python => python(c, &mut budget),
        Kind::Npm => npm(c, &mut budget),
        Kind::Filesystem => filesystem(c, &mut budget),
        _ => bail!("unsupported file collector"),
    }
}
fn parse_apk(c: &Collector, text: &str) -> Result<Vec<Software>> {
    let mut items: Vec<Software> = Vec::new();
    for record in text.split("\n\n").filter(|s: &&str| !s.trim().is_empty()) {
        let value = |prefix: &str| -> Option<&str> {
            record
                .lines()
                .find_map(|line: &str| line.strip_prefix(prefix))
        };
        let name: &str = value("P:").context("APK record missing name")?;
        let version: &str = value("V:").context("APK record missing version")?;
        items.push(Software::new(
            c,
            name,
            version,
            value("A:").unwrap_or(""),
            None,
            "APK installed database",
            "",
        ));
    }
    Ok(items)
}
fn parse_cargo(c: &Collector, text: &str) -> Result<Vec<Software>> {
    let data: toml::Value = toml::from_str::<toml::Value>(text)?;
    let records: &toml::map::Map<String, toml::Value> = data
        .get("v1")
        .and_then(toml::Value::as_table)
        .context("Cargo metadata missing v1 table")?;
    let mut items: Vec<Software> = Vec::new();
    for (key, bins) in records {
        let mut parts: std::str::SplitN<'_, char> = key.splitn(3, ' ');
        let name: &str = parts.next().context("Cargo record missing name")?;
        let version: &str = parts.next().context("Cargo record missing version")?;
        let origin: &str = parts.next().context("Cargo record missing origin")?;
        let bins: &Vec<toml::Value> = bins.as_array().context("Cargo binaries must be an array")?;
        // Only count tracked packages with at least one binary still present.
        let mut present: bool = false;
        for bin in bins {
            let bin: &str = bin.as_str().context("Cargo binary name must be a string")?;
            if Path::new(bin).components().count() != 1 || bin == "." || bin == ".." {
                bail!("invalid Cargo binary name");
            }
            match fs::metadata(c.path.join("bin").join(bin)) {
                Ok(m) => present |= m.is_file(),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => (),
                Err(e) => return Err(e.into()),
            }
        }
        if present {
            items.push(Software::new(
                c,
                name,
                version,
                "",
                Some(c.path.clone()),
                &format!("Cargo .crates.toml {origin}; binary present"),
                origin,
            ));
        }
    }
    Ok(items)
}
fn python(c: &Collector, budget: &mut Budget) -> Result<Vec<Software>> {
    let mut items: Vec<Software> = Vec::new();
    for entry in fs::read_dir(&c.path)? {
        budget.tick()?;
        let path: PathBuf = entry?.path();
        if path
            .extension()
            .is_none_or(|ext: &std::ffi::OsStr| ext != "dist-info" && ext != "egg-info")
        {
            continue;
        }
        let metadata: PathBuf = if path.is_dir() {
            path.join(
                if path
                    .extension()
                    .is_some_and(|x: &std::ffi::OsStr| x == "dist-info")
                {
                    "METADATA"
                } else {
                    "PKG-INFO"
                },
            )
        } else {
            path.clone()
        };
        let text: String = budget.read(&metadata)?;
        let headers: &str = text.split("\n\n").next().unwrap_or("");
        let field = |key: &str| -> Option<&str> {
            headers
                .lines()
                .find_map(|s: &str| s.strip_prefix(key))
                .map(str::trim)
        };
        let name: &str = field("Name:")
            .filter(|s: &&str| !s.is_empty())
            .context("Python metadata missing Name")?;
        let version: &str = field("Version:")
            .filter(|s: &&str| !s.is_empty())
            .context("Python metadata missing Version")?;
        items.push(Software::new(
            c,
            name,
            version,
            "",
            Some(path),
            "Python installed distribution metadata",
            "",
        ));
    }
    Ok(items)
}
fn npm(c: &Collector, budget: &mut Budget) -> Result<Vec<Software>> {
    let mut roots: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(&c.path)? {
        budget.tick()?;
        let entry: fs::DirEntry = entry?;
        let name: std::ffi::OsString = entry.file_name();
        if name.as_encoded_bytes().starts_with(b".") {
            continue;
        }
        if name.as_encoded_bytes().starts_with(b"@") {
            for scoped in fs::read_dir(entry.path())? {
                budget.tick()?;
                roots.push(scoped?.path());
            }
        } else {
            roots.push(entry.path());
        }
    }
    let mut items: Vec<Software> = Vec::new();
    for root in roots {
        let path: PathBuf = root.join("package.json");
        let text: String = budget.read(&path)?;
        let data: serde_json::Value = serde_json::from_str::<serde_json::Value>(&text)?;
        let name: &str = data
            .get("name")
            .and_then(|v: &serde_json::Value| v.as_str())
            .filter(|s: &&str| !s.is_empty())
            .context("npm metadata missing name")?;
        let version: &str = data
            .get("version")
            .and_then(|v: &serde_json::Value| v.as_str())
            .context("npm metadata missing version")?;
        items.push(Software::new(
            c,
            name,
            version,
            "",
            Some(root.clone()),
            "installed node_modules/package.json",
            &root.to_string_lossy(),
        ));
    }
    Ok(items)
}
fn filesystem(c: &Collector, budget: &mut Budget) -> Result<Vec<Software>> {
    if !fs::metadata(&c.path)?.is_dir() {
        bail!("filesystem root must be a directory: {}", c.path.display());
    }
    let mut items: Vec<Software> = Vec::new();
    let mut seen: HashSet<PathBuf> = HashSet::<PathBuf>::new();
    for entry in WalkDir::new(&c.path)
        .max_depth(c.max_depth)
        .follow_links(false)
    {
        budget.tick()?;
        let entry: walkdir::DirEntry = entry?;
        if entry.depth() == 0 || entry.file_type().is_dir() {
            continue;
        }
        let path: &Path = entry.path();
        let metadata: fs::Metadata = match fs::metadata(path) {
            Ok(m) => m,
            Err(e)
                if e.kind() == std::io::ErrorKind::NotFound && entry.file_type().is_symlink() =>
            {
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        if !metadata.is_file() || metadata.permissions().mode() & 0o111 == 0 {
            continue;
        }
        let resolved: PathBuf = fs::canonicalize(path)?;
        if !seen.insert(resolved.clone()) {
            continue;
        }
        let name: std::borrow::Cow<'_, str> = resolved
            .file_name()
            .context("executable has no filename")?
            .to_string_lossy();
        items.push(Software::new(
            c,
            &name,
            "",
            "",
            Some(resolved.clone()),
            "executable permission bits; version unknown; not executed",
            &resolved.to_string_lossy(),
        ));
    }
    Ok(items)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn c(kind: Kind, path: &Path) -> Collector {
        Collector {
            id: "test".into(),
            kind,
            path: path.into(),
            max_depth: 4,
        }
    }
    #[test]
    fn dpkg_filters_removed_and_rejects_malformed() {
        let c: Collector = c(Kind::Dpkg, Path::new("/usr/bin/dpkg-query"));
        let items: Vec<Software> = parse_command(
            &c,
            "libssl3:amd64\t3.0.11-1~deb12u2+b1\tamd64\tinstalled\topenssl\t3.0.11-1~deb12u2\n\
             old\t1\tall\tconfig-files\told\t1\n\
             curl\t7.88.1-10\tamd64\tinstalled\tcurl\t7.88.1-10\n",
        )
        .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].version.as_deref(), Some("3.0.11-1~deb12u2+b1"));
        assert_eq!(items[0].source_package.as_deref(), Some("openssl"));
        assert_eq!(items[0].source_version.as_deref(), Some("3.0.11-1~deb12u2"));
        // The source version is only kept when it differs from the binary version.
        assert_eq!(items[1].source_package.as_deref(), Some("curl"));
        assert_eq!(items[1].source_version, None);
        assert!(parse_command(&c, "broken").is_err());
    }
    #[test]
    fn parses_package_formats() {
        let root: &Path = Path::new("/tmp");
        let rpm: Vec<Software> = parse_command(
            &c(Kind::Rpm, root),
            "libopenssl3\t0:3.0.8-150500.5.8.1\tx86_64\topenssl-3-3.0.8-150500.5.8.1.src.rpm\n\
             gpg-pubkey\t0:1-2\t(none)\t(none)\n",
        )
        .unwrap();
        assert_eq!(rpm[0].architecture, "x86_64");
        assert_eq!(rpm[0].source_package.as_deref(), Some("openssl-3"));
        assert_eq!(rpm[1].source_package, None);
        assert!(parse_command(&c(Kind::Rpm, root), "kernel\t0:6.1-2\tx86_64\n").is_err());
        assert_eq!(
            parse_command(&c(Kind::Pacman, root), "linux 6.1-1\n")
                .unwrap()
                .len(),
            1
        );
        assert_eq!(parse_command(&c(Kind::Snap, root), "Name Version Rev Tracking Publisher Notes\nhello 1.0 42 latest/stable canonical -\n").unwrap().len(), 1);
        let fp: Vec<Software> = parse_command(
            &c(Kind::Flatpak, root),
            "org.app.Test\t\tx86_64\tstable\tsystem\norg.app.Test\t\tx86_64\tbeta\tsystem\n",
        )
        .unwrap();
        assert!(fp[0].version.is_none());
        assert_ne!(fp[0].installation_id, fp[1].installation_id);
        assert_eq!(
            parse_apk(&c(Kind::Apk, root), "P:busybox\nV:1.2-r0\nA:x86_64\n\n")
                .unwrap()
                .len(),
            1
        );
    }
    #[test]
    fn passive_scans_and_scoped_npm() {
        let tmp: tempfile::TempDir = tempfile::tempdir().unwrap();
        let root: &Path = tmp.path();
        fs::create_dir(root.join("demo-1.dist-info")).unwrap();
        fs::write(
            root.join("demo-1.dist-info/METADATA"),
            "Name: demo\nVersion: 1.0\n\nDescription",
        )
        .unwrap();
        assert_eq!(
            collect_files(&c(Kind::Python, root), &Config::default()).unwrap()[0].name,
            "demo"
        );
        let modules: PathBuf = root.join("node_modules");
        fs::create_dir_all(modules.join("@scope/app")).unwrap();
        fs::write(
            modules.join("@scope/app/package.json"),
            r#"{"name":"@scope/app","version":"2.0"}"#,
        )
        .unwrap();
        assert_eq!(
            collect_files(&c(Kind::Npm, &modules), &Config::default()).unwrap()[0]
                .version
                .as_deref(),
            Some("2.0")
        );
        let binary: PathBuf = root.join("do-not-run");
        fs::write(&binary, "#!/bin/sh\nexit 99\n").unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink(&binary, root.join("alias")).unwrap();
        std::os::unix::fs::symlink(root, root.join("loop")).unwrap();
        let files: Vec<Software> =
            collect_files(&c(Kind::Filesystem, root), &Config::default()).unwrap();
        assert_eq!(files.len(), 1);
        assert!(files[0].version.is_none());
    }
    #[test]
    fn cargo_checks_presence_and_scan_limits_fail_closed() {
        let tmp: tempfile::TempDir = tempfile::tempdir().unwrap();
        fs::create_dir(tmp.path().join("bin")).unwrap();
        fs::write(tmp.path().join("bin/rg"), "binary").unwrap();
        let c: Collector = c(Kind::Cargo, tmp.path());
        let data: &str = "[v1]\n\"ripgrep 14.1.1 (registry+https://example.test)\" = [\"rg\"]\n\"gone 1.0.0 (registry+https://example.test)\" = [\"gone\"]\n";
        assert_eq!(parse_cargo(&c, data).unwrap().len(), 1);
        let cfg: Config = Config {
            max_output_bytes: 1,
            ..Config::default()
        };
        fs::write(tmp.path().join(".crates.toml"), data).unwrap();
        assert!(collect_files(&c, &cfg).is_err());
    }
}
