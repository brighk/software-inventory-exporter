-- Source packages are needed for Debian, Ubuntu and SUSE advisories.
ALTER TABLE installations ADD COLUMN source_package TEXT;
ALTER TABLE installations ADD COLUMN source_version TEXT;
-- OSV.dev results per (ecosystem, package, version): a JSON array of advisory IDs.
CREATE TABLE osv_queries (
    ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL,
    fetched_at INTEGER NOT NULL, vulns TEXT NOT NULL,
    PRIMARY KEY(ecosystem,name,version)
);
-- Summaries of OSV advisories; refetched when OSV reports a newer modified time.
CREATE TABLE osv_vulns (
    id TEXT PRIMARY KEY, modified TEXT NOT NULL, fetched_at INTEGER NOT NULL, data TEXT NOT NULL
);
CREATE TABLE osv_state (
    id INTEGER PRIMARY KEY CHECK(id=1), last_attempt INTEGER NOT NULL,
    last_success INTEGER, success INTEGER NOT NULL, error TEXT
);
PRAGMA user_version=4;
