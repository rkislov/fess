package threatfeed

import "testing"

const sampleThreatFoxCSV = `################################################################
# ThreatFox IOCs
################################################################
# "first_seen_utc","ioc_id","ioc_value","ioc_type","threat_type","fk_malware","malware_alias","malware_printable","last_seen_utc","confidence_level","is_compromised","reference","tags","anonymous","reporter"
"2026-05-13 03:35:05", "1811703", "172.241.164.247:5655", "ip:port", "botnet_cc", "win.rms", "None", "RMS", "", "100", "False", "None", "RemoteManipulator", "0", "abuse_ch"
"2026-05-12 14:53:02", "1810898", "3941d2e13d9ed19d7f867bd266338e9ec0c8eb986ff656743c83c6d1a03555cc", "sha256_hash", "payload", "win.asyncrat", "None", "AsyncRAT", "", "90", "False", "None", "asyncrat", "0", "Lenny_3BO"
`

func TestParseThreatFoxCSVWithCommentHeader(t *testing.T) {
	p, err := ParseThreatFoxCSV([]byte(sampleThreatFoxCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(p.IPs) != 1 {
		t.Fatalf("ips: %v", p.IPs)
	}
	if len(p.Hashes) != 1 {
		t.Fatalf("hashes: %v", p.Hashes)
	}
}

func TestReadThreatFoxCSVRecordsSkipsBanner(t *testing.T) {
	rows, err := readThreatFoxCSVRecords([]byte(sampleThreatFoxCSV))
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) < 3 {
		t.Fatalf("rows: %d", len(rows))
	}
	if rows[0][2] != "ioc_value" {
		t.Fatalf("header col2: %q", rows[0][2])
	}
}
