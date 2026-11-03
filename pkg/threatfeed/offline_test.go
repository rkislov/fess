package threatfeed

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
)

func testOfflineZip(t *testing.T, corrupt bool) []byte {
	t.Helper()
	files := map[string]string{"ips.txt": "185.220.101.1\n", "hashes.txt": "da39a3ee5e6b4b0d3255bfef95601890afd80709\n", "domains.txt": "malware-host.xyz\n", "urls.txt": "https://malware-host.xyz/Case?Token=AbC#/Login\n"}
	m := OfflineManifest{Format: OfflineFormat, Files: map[string]OfflineFile{}}
	for name, body := range files {
		h := sha256.Sum256([]byte(body))
		m.Files[name] = OfflineFile{SHA256: hex.EncodeToString(h[:]), Bytes: int64(len(body)), Count: 1}
	}
	if corrupt {
		files["ips.txt"] = "185.220.101.2\n"
	}
	raw, _ := json.Marshal(m)
	files["manifest.json"] = string(raw)
	var b bytes.Buffer
	z := zip.NewWriter(&b)
	for name, body := range files {
		w, e := z.Create(name)
		if e != nil {
			t.Fatal(e)
		}
		w.Write([]byte(body))
	}
	z.Close()
	return b.Bytes()
}
func TestOfflineVerifiesAndPreservesEveryIOCType(t *testing.T) {
	raw := testOfflineZip(t, false)
	b, e := ParseOffline(bytes.NewReader(raw), int64(len(raw)))
	if e != nil {
		t.Fatal(e)
	}
	if len(b.IPs) != 1 || len(b.Hashes) != 1 || len(b.Domains) != 1 || len(b.URLs) != 1 || b.URLs[0] != "https://malware-host.xyz/Case?Token=AbC#/Login" {
		t.Fatalf("lost indicators: %+v", b)
	}
	raw = testOfflineZip(t, true)
	if _, e = ParseOffline(bytes.NewReader(raw), int64(len(raw))); e == nil {
		t.Fatal("accepted checksum mismatch")
	}
}
func TestSHA1BodyMatching(t *testing.T) {
	body := []byte("offline hash matching")
	sum := sha1.Sum(body)
	hash := hex.EncodeToString(sum[:])
	s := NewHashSet([]string{hash})
	if h, ok := s.MatchBody(body); !ok || h != hash {
		t.Fatal("SHA1 did not match")
	}
}
