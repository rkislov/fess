ALTER TABLE threat_feed_file_hashes DROP CONSTRAINT IF EXISTS threat_feed_file_hashes_hash_alg_check;
ALTER TABLE threat_feed_file_hashes ADD CONSTRAINT threat_feed_file_hashes_hash_alg_check CHECK(hash_alg IN ('md5','sha1','sha256'));
CREATE TABLE IF NOT EXISTS threat_feed_web_iocs(id TEXT PRIMARY KEY, indicator_type TEXT NOT NULL, value TEXT NOT NULL);
