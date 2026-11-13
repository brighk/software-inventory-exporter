use crate::{model, protocol::Submission};
use anyhow::{Result, bail};
use rusqlite::{Connection, OptionalExtension, params};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{path::Path, time::Duration};

pub struct Database(pub(crate) Connection);
#[derive(Debug)]
pub struct Conflict;
impl std::fmt::Display for Conflict {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("sequence conflict")
    }
}
impl std::error::Error for Conflict {}

impl Database {
    pub fn open(path: &Path) -> Result<Self> {
        let connection = Connection::open(path)?;
        connection.busy_timeout(Duration::from_secs(5))?;
        connection.execute_batch("PRAGMA foreign_keys=ON;")?;
        // Switching a new file to WAL can return SQLITE_BUSY without invoking the busy
        // handler when another process opens it at the same moment; retry briefly.
        let started = std::time::Instant::now();
        loop {
            match connection.execute_batch("PRAGMA journal_mode=WAL;") {
                Err(rusqlite::Error::SqliteFailure(e, _))
                    if e.code == rusqlite::ErrorCode::DatabaseBusy
                        && started.elapsed() < Duration::from_secs(5) =>
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                result => break result?,
            }
        }
        let mut connection = connection;
        // The server and assessment worker may open a new database concurrently:
        // read the version under the write lock so only one of them migrates.
        let tx = connection.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let version: i64 = tx.query_row("PRAGMA user_version", [], |r| r.get(0))?;
        if version > 4 {
            bail!("database schema is newer than this server");
        }
        if version == 0 {
            tx.execute_batch(include_str!("schema.sql"))?;
        }
        if version < 2 {
            tx.execute_batch(include_str!("assessment-schema.sql"))?;
        }
        if version < 3 {
            tx.execute_batch(include_str!("nvd-schema.sql"))?;
        }
        if version < 4 {
            tx.execute_batch(include_str!("osv-schema.sql"))?;
        }
        tx.commit()?;
        Ok(Self(connection))
    }

    /// Returns false for an identical retry. Rejects sequence reuse with different content.
    pub fn ingest(&mut self, submission: &Submission) -> Result<bool> {
        submission.validate()?;
        let encoded = serde_json::to_vec(submission)?;
        let digest = format!("{:x}", Sha256::digest(&encoded));
        let tx = self
            .0
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let previous: Option<String> = tx
            .query_row(
                "SELECT digest FROM scans WHERE host_id=?1 AND sequence=?2",
                params![submission.host.id, submission.sequence],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(previous) = previous {
            if previous != digest {
                return Err(Conflict.into());
            }
            return Ok(false);
        }
        let latest: Option<i64> = tx
            .query_row(
                "SELECT last_sequence FROM hosts WHERE id=?1",
                [&submission.host.id],
                |r| r.get(0),
            )
            .optional()?;
        if latest.is_some_and(|n| submission.sequence <= n) {
            return Err(Conflict.into());
        }
        let now = model::now() as i64;
        let host = &submission.host;
        tx.execute("INSERT INTO hosts(id,hostname,os,os_version,architecture,last_seen,last_sequence)
            VALUES (?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(id) DO UPDATE SET
            hostname=excluded.hostname,os=excluded.os,os_version=excluded.os_version,
            architecture=excluded.architecture,last_seen=excluded.last_seen,last_sequence=excluded.last_sequence",
            params![host.id,host.hostname,host.os,host.os_version,host.architecture,now,submission.sequence])?;
        tx.execute("INSERT INTO scans(host_id,sequence,received_at,success,digest) VALUES (?1,?2,?3,?4,?5)",
            params![host.id,submission.sequence,now,submission.inventory.collectors.values().all(|s| s.success),digest])?;
        // Omitted collectors remain visible, explicitly inactive, until an administrator removes them.
        tx.execute(
            "UPDATE collectors SET active=0 WHERE host_id=?1",
            [&host.id],
        )?;
        for (id, state) in &submission.inventory.collectors {
            tx.execute("INSERT INTO collectors(host_id,id,source,path,active,success,last_attempt,last_success,error,sequence)
                VALUES (?1,?2,?3,?4,1,?5,?6,?7,?8,?9)
                ON CONFLICT(host_id,id) DO UPDATE SET source=excluded.source,path=excluded.path,active=1,
                success=excluded.success,last_attempt=excluded.last_attempt,
                last_success=CASE WHEN excluded.success THEN excluded.last_success ELSE collectors.last_success END,
                error=excluded.error,sequence=excluded.sequence",
                params![host.id,id,state.source,state.path.to_str(),state.success,
                    state.last_attempt_timestamp_seconds,if state.success { state.last_success_timestamp_seconds } else { None },
                    state.error,submission.sequence])?;
            if !state.success {
                continue;
            }
            tx.execute(
                "DELETE FROM installations WHERE host_id=?1 AND collector_id=?2",
                params![host.id, id],
            )?;
            for item in &state.software {
                tx.execute("INSERT INTO installations(host_id,collector_id,installation_id,name,version,source,architecture,path,evidence,last_seen,source_package,source_version)
                    VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12)",
                    params![host.id,id,item.installation_id,item.name,item.version,item.source.name(),
                        item.architecture,item.path.as_ref().and_then(|p| p.to_str()),item.evidence,state.last_attempt_timestamp_seconds,
                        item.source_package,item.source_version])?;
            }
        }
        tx.commit()?;
        Ok(true)
    }

    /// Deletes scan summaries received before `cutoff`, keeping each host's latest
    /// scan: its digest lets an agent that missed the acknowledgment retry safely.
    pub fn prune_scans(&self, cutoff: i64) -> Result<usize> {
        Ok(self.0.execute(
            "DELETE FROM scans WHERE received_at < ?1
             AND sequence < (SELECT last_sequence FROM hosts WHERE hosts.id = scans.host_id)",
            [cutoff],
        )?)
    }

    pub fn hosts(&self, limit: i64, offset: i64) -> Result<Vec<Value>> {
        let mut stmt = self.0.prepare("SELECT id,hostname,os,os_version,architecture,last_seen,last_sequence FROM hosts ORDER BY id LIMIT ?1 OFFSET ?2")?;
        let rows = stmt.query_map(params![limit,offset], |r| Ok(json!({
            "id":r.get::<_,String>(0)?,"hostname":r.get::<_,String>(1)?,"os":r.get::<_,String>(2)?,
            "os_version":r.get::<_,String>(3)?,"architecture":r.get::<_,String>(4)?,
            "last_seen":r.get::<_,i64>(5)?,"last_sequence":r.get::<_,i64>(6)?
        })))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn installations(
        &self,
        host: Option<&str>,
        name: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Value>> {
        let mut stmt = self.0.prepare(
            "SELECT i.host_id,i.collector_id,i.installation_id,i.name,i.version,i.source,
            i.architecture,i.path,i.evidence,i.last_seen,c.success,c.active,i.source_package,i.source_version FROM installations i
            JOIN collectors c ON c.host_id=i.host_id AND c.id=i.collector_id
            WHERE (?1 IS NULL OR i.host_id=?1) AND (?2 IS NULL OR i.name=?2)
            ORDER BY i.host_id,i.collector_id,i.installation_id,i.version LIMIT ?3 OFFSET ?4",
        )?;
        let rows = stmt.query_map(params![host,name,limit,offset], |r| Ok(json!({
            "host_id":r.get::<_,String>(0)?,"collector_id":r.get::<_,String>(1)?,"installation_id":r.get::<_,String>(2)?,
            "name":r.get::<_,String>(3)?,"version":r.get::<_,Option<String>>(4)?,"source":r.get::<_,String>(5)?,
            "architecture":r.get::<_,String>(6)?,"path":r.get::<_,Option<String>>(7)?,"evidence":r.get::<_,String>(8)?,
            "last_seen":r.get::<_,i64>(9)?,"collector_success":r.get::<_,bool>(10)?,"collector_active":r.get::<_,bool>(11)?,
            "source_package":r.get::<_,Option<String>>(12)?,"source_version":r.get::<_,Option<String>>(13)?
        })))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }

    pub fn collectors(&self, host: &str) -> Result<Vec<Value>> {
        let mut stmt = self.0.prepare("SELECT id,source,path,active,success,last_attempt,last_success,error,sequence FROM collectors WHERE host_id=?1 ORDER BY id")?;
        let rows = stmt.query_map([host], |r| Ok(json!({
            "id":r.get::<_,String>(0)?,"source":r.get::<_,String>(1)?,"path":r.get::<_,String>(2)?,
            "active":r.get::<_,bool>(3)?,"success":r.get::<_,bool>(4)?,"last_attempt":r.get::<_,i64>(5)?,
            "last_success":r.get::<_,Option<i64>>(6)?,"error":r.get::<_,Option<String>>(7)?,"sequence":r.get::<_,i64>(8)?
        })))?;
        Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::{Collector, Kind},
        model::{Inventory, Software},
        protocol::Host,
    };

    fn submission(sequence: i64) -> Submission {
        let c = Collector {
            id: "os".into(),
            kind: Kind::Pacman,
            path: "/usr/bin/pacman".into(),
            max_depth: 1,
        };
        let mut inventory = Inventory {
            schema_version: 1,
            initial_scan_complete: true,
            ..Inventory::default()
        };
        inventory.apply(
            &c,
            Ok(vec![Software::new(
                &c,
                "demo",
                "1-1",
                "",
                None,
                "package database",
                "",
            )]),
            100,
            0.1,
        );
        Submission {
            protocol_version: 1,
            host: Host {
                id: "arch-01".into(),
                hostname: "desktop".into(),
                os: "arch".into(),
                os_version: "rolling".into(),
                architecture: "x86_64".into(),
            },
            sequence,
            inventory,
        }
    }

    #[test]
    fn replacement_failures_retries_ordering_and_persistence() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("inventory.db");
        let mut db = Database::open(&path).unwrap();
        let first = submission(1);
        assert!(db.ingest(&first).unwrap());
        assert!(!db.ingest(&first).unwrap());
        let mut changed = first.clone();
        changed.host.hostname = "changed".into();
        assert!(db.ingest(&changed).is_err());
        let mut failure = submission(3);
        let state = failure.inventory.collectors.get_mut("os").unwrap();
        state.success = false;
        state.error = Some("failed".into());
        state.software.clear();
        db.ingest(&failure).unwrap();
        let rows = db.installations(None, None, 100, 0).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0]["collector_success"], false);
        assert!(db.ingest(&submission(2)).is_err());
        // A failed first scan cannot seed the server with unverified cached records.
        let mut other = failure.clone();
        other.host.id = "arch-02".into();
        other.inventory = first.inventory.clone();
        let state = other.inventory.collectors.get_mut("os").unwrap();
        state.success = false;
        state.error = Some("failed".into());
        db.ingest(&other).unwrap();
        assert!(
            db.installations(Some("arch-02"), None, 100, 0)
                .unwrap()
                .is_empty()
        );
        let mut omitted = submission(4);
        omitted.inventory.collectors.clear();
        db.ingest(&omitted).unwrap();
        assert_eq!(
            db.installations(Some("arch-01"), None, 100, 0).unwrap()[0]["collector_active"],
            false
        );
        let mut empty = submission(5);
        empty
            .inventory
            .collectors
            .get_mut("os")
            .unwrap()
            .software
            .clear();
        db.ingest(&empty).unwrap();
        assert!(db.installations(None, None, 100, 0).unwrap().is_empty());
        drop(db);
        let mut db = Database::open(&path).unwrap();
        assert_eq!(db.hosts(100, 0).unwrap().len(), 2);
        assert!(!db.ingest(&first).unwrap());
        assert_eq!(db.hosts(100, 0).unwrap()[0]["last_sequence"], 5);
    }

    #[test]
    fn migrates_version_3_database() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("old.db");
        let old = Connection::open(&path).unwrap();
        for schema in [
            include_str!("schema.sql"),
            include_str!("assessment-schema.sql"),
            include_str!("nvd-schema.sql"),
        ] {
            old.execute_batch(schema).unwrap();
        }
        drop(old);
        let mut db = Database::open(&path).unwrap();
        let version: i64 =
            db.0.query_row("PRAGMA user_version", [], |r| r.get(0))
                .unwrap();
        assert_eq!(version, 4);
        let mut payload = submission(1);
        let item = &mut payload.inventory.collectors.get_mut("os").unwrap().software[0];
        item.source_package = Some("demo-src".into());
        db.ingest(&payload).unwrap();
        assert_eq!(
            db.installations(None, None, 10, 0).unwrap()[0]["source_package"],
            "demo-src"
        );
    }

    #[test]
    fn prunes_old_scans_but_keeps_latest_for_retries() {
        let mut db = Database::open(Path::new(":memory:")).unwrap();
        for sequence in 1..=3 {
            assert!(db.ingest(&submission(sequence)).unwrap());
        }
        let count = |db: &Database| -> i64 {
            db.0.query_row("SELECT COUNT(*) FROM scans", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(db.prune_scans(0).unwrap(), 0);
        assert_eq!(db.prune_scans(i64::MAX).unwrap(), 2);
        assert_eq!(count(&db), 1);
        // The lost-acknowledgment retry of the latest scan is still a duplicate, not a conflict.
        assert!(!db.ingest(&submission(3)).unwrap());
        assert!(db.ingest(&submission(2)).is_err());
        assert!(db.ingest(&submission(4)).unwrap());
    }

    #[test]
    fn rejects_invalid_payload_without_mutation_and_preserves_parallel_versions() {
        let mut db = Database::open(Path::new(":memory:")).unwrap();
        let mut payload = submission(1);
        payload.inventory.collectors.get_mut("os").unwrap().software[0].scope = "wrong".into();
        assert!(db.ingest(&payload).is_err());
        assert!(db.hosts(100, 0).unwrap().is_empty());
        let mut payload = submission(1);
        let software = &mut payload.inventory.collectors.get_mut("os").unwrap().software;
        let mut second = software[0].clone();
        second.version = Some("2-1".into());
        software.push(second);
        db.ingest(&payload).unwrap();
        assert_eq!(
            db.installations(None, Some("demo"), 100, 0).unwrap().len(),
            2
        );
        assert!(
            db.installations(None, Some("absent"), 100, 0)
                .unwrap()
                .is_empty()
        );
    }
}
