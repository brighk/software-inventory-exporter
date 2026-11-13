-- NVD CVE details cached per CVE ID; found=0 records a lookup with no NVD record.
CREATE TABLE nvd_cves (
    id TEXT PRIMARY KEY, fetched_at INTEGER NOT NULL, found INTEGER NOT NULL,
    vuln_status TEXT, published TEXT, last_modified TEXT, description TEXT,
    cvss_score REAL, cvss_severity TEXT, cvss_version TEXT, cvss_vector TEXT,
    cvss_source TEXT, cvss_primary INTEGER
);
CREATE TABLE nvd_state (
    id INTEGER PRIMARY KEY CHECK(id=1), last_attempt INTEGER NOT NULL,
    last_success INTEGER, success INTEGER NOT NULL, error TEXT
);
PRAGMA user_version=3;
