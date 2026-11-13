CREATE TABLE advisories (
    id TEXT PRIMARY KEY, source TEXT NOT NULL, data TEXT NOT NULL
);
CREATE TABLE assessment_state (
    id INTEGER PRIMARY KEY CHECK(id=1), last_attempt INTEGER NOT NULL,
    last_success INTEGER, success INTEGER NOT NULL, error TEXT,
    feed_sha256 TEXT, feed_source TEXT
);
CREATE TABLE assessments (
    host_id TEXT NOT NULL REFERENCES hosts(id), collector_id TEXT NOT NULL,
    installation_id TEXT NOT NULL, version TEXT NOT NULL, name TEXT NOT NULL,
    sequence INTEGER NOT NULL, assessed_at INTEGER NOT NULL,
    status TEXT NOT NULL, findings TEXT NOT NULL,
    PRIMARY KEY(host_id,collector_id,installation_id,version)
);
PRAGMA user_version=2;
