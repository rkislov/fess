-- ThreatFox file hash IOCs (MD5 / SHA256) for upload body matching.
CREATE TABLE IF NOT EXISTS threat_feed_file_hashes (
  hash TEXT PRIMARY KEY,
  hash_alg TEXT NOT NULL CHECK (hash_alg IN ('md5', 'sha256'))
);

CREATE INDEX IF NOT EXISTS idx_threat_feed_file_hashes_alg ON threat_feed_file_hashes (hash_alg);
