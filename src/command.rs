use anyhow::{Context, Result, bail};
use std::{path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
};

async fn read_limited(reader: impl AsyncRead + Unpin, limit: usize) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader
        .take(limit as u64 + 1)
        .read_to_end(&mut bytes)
        .await?;
    if bytes.len() > limit {
        bail!("command output exceeded {limit} bytes");
    }
    Ok(bytes)
}

/// Only configured, trusted package-manager binaries are executed. No shell.
pub async fn run(path: &Path, args: &[&str], timeout: Duration, limit: usize) -> Result<String> {
    let mut child = Command::new(path)
        .args(args)
        .env("LC_ALL", "C")
        .env("TERM", "dumb")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("start {}", path.display()))?;
    let stdout = child.stdout.take().context("missing stdout pipe")?;
    let stderr = child.stderr.take().context("missing stderr pipe")?;
    let operation = async {
        let (out, err, status) = tokio::try_join!(
            read_limited(stdout, limit),
            read_limited(stderr, limit),
            async { child.wait().await.map_err(anyhow::Error::from) }
        )?;
        if !status.success() {
            bail!(
                "command exited {status}: {}",
                String::from_utf8_lossy(&err)
                    .chars()
                    .take(2048)
                    .collect::<String>()
            );
        }
        String::from_utf8(out).context("command output is not UTF-8")
    };
    let result = match tokio::time::timeout(timeout, operation).await {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!(
            "command timed out after {}s",
            timeout.as_secs()
        )),
    };
    if result.is_err() {
        // Kill and reap the direct child; arbitrary command wrappers are unsupported.
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn bounds_output_and_timeout() {
        assert!(
            run(
                Path::new("/usr/bin/printf"),
                &["123456"],
                Duration::from_secs(1),
                3
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("exceeded")
        );
        assert!(
            run(
                Path::new("/usr/bin/sleep"),
                &["2"],
                Duration::from_millis(20),
                1024
            )
            .await
            .unwrap_err()
            .to_string()
            .contains("timed out")
        );
    }
    #[tokio::test]
    async fn reports_exit_failure() {
        assert!(
            run(
                Path::new("/usr/bin/false"),
                &[],
                Duration::from_secs(1),
                1024
            )
            .await
            .is_err()
        );
    }
}
