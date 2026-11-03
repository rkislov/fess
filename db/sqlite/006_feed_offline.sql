ALTER TABLE threat_feed_file_hashes RENAME TO threat_feed_file_hashes_old;
CREATE TABLE threat_feed_file_hashes(hash TEXT PRIMARY KEY,hash_alg TEXT NOT NULL CHECK(hash_alg IN ('md5','sha1','sha256')));
INSERT INTO threat_feed_file_hashes SELECT * FROM threat_feed_file_hashes_old;
DROP TABLE threat_feed_file_hashes_old;
CREATE INDEX idx_threat_feed_file_hashes_alg ON threat_feed_file_hashes(hash_alg);
CREATE TABLE IF NOT EXISTS threat_feed_web_iocs(id TEXT PRIMARY KEY,indicator_type TEXT NOT NULL,value TEXT NOT NULL);
