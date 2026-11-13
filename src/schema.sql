BEGIN IMMEDIATE;
CREATE TABLE hosts (
    id TEXT PRIMARY KEY, hostname TEXT NOT NULL, os TEXT NOT NULL,
    os_version TEXT NOT NULL, architecture TEXT NOT NULL,
    last_seen INTEGER NOT NULL, last_sequence INTEGER NOT NULL
);
CREATE TABLE scans (
    host_id TEXT NOT NULL REFERENCES hosts(id), sequence INTEGER NOT NULL,
    received_at INTEGER NOT NULL, success INTEGER NOT NULL, digest TEXT NOT NULL,
    PRIMARY KEY(host_id,sequence)
);
CREATE TABLE collectors (
    host_id TEXT NOT NULL REFERENCES hosts(id), id TEXT NOT NULL,
    source TEXT NOT NULL, path TEXT NOT NULL, active INTEGER NOT NULL,
    success INTEGER NOT NULL, last_attempt INTEGER NOT NULL, last_success INTEGER,
    error TEXT, sequence INTEGER NOT NULL, PRIMARY KEY(host_id,id)
);
CREATE TABLE installations (
    host_id TEXT NOT NULL, collector_id TEXT NOT NULL, installation_id TEXT NOT NULL,
    name TEXT NOT NULL, version TEXT, source TEXT NOT NULL, architecture TEXT NOT NULL,
    path TEXT, evidence TEXT NOT NULL, last_seen INTEGER NOT NULL,
    FOREIGN KEY(host_id,collector_id) REFERENCES collectors(host_id,id)
);
-- Versions are included because RPM can retain several versions of one package.
CREATE UNIQUE INDEX installation_identity ON installations(host_id,collector_id,installation_id,COALESCE(version,''));
CREATE INDEX installation_name ON installations(name,host_id);
PRAGMA user_version=1;
COMMIT;
