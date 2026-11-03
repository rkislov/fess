package threatfeed

import (
	"archive/zip"
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
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

func TestOfflineBotListsMustBeCompleteAndVerified(t *testing.T) {
	base := testOfflineZip(t, false)
	z, _ := zip.NewReader(bytes.NewReader(base), int64(len(base)))
	files := map[string][]byte{}
	for _, f := range z.File {
		r, _ := f.Open()
		files[f.Name], _ = io.ReadAll(r)
		r.Close()
	}
	var m OfflineManifest
	json.Unmarshal(files["manifest.json"], &m)
	for name, body := range map[string]string{"asns.txt": "12345\n", "bot-cidrs.txt": "185.220.101.0/24\n"} {
		files[name] = []byte(body)
		sum := sha256.Sum256([]byte(body))
		m.Files[name] = OfflineFile{hex.EncodeToString(sum[:]), int64(len(body)), 1}
	}
	encode := func() []byte {
		raw, _ := json.Marshal(m)
		files["manifest.json"] = raw
		var b bytes.Buffer
		w := zip.NewWriter(&b)
		for name, body := range files {
			f, _ := w.Create(name)
			f.Write(body)
		}
		w.Close()
		return b.Bytes()
	}
	raw := encode()
	b, e := ParseOffline(bytes.NewReader(raw), int64(len(raw)))
	if e != nil || !b.HasBotLists || len(b.ASNs) != 1 || b.ASNs[0] != 12345 || len(b.BotCIDRs) != 1 {
		t.Fatalf("lost bot lists: %+v %v", b, e)
	}
	delete(m.Files, "bot-cidrs.txt")
	raw = encode()
	if _, e = ParseOffline(bytes.NewReader(raw), int64(len(raw))); e == nil {
		t.Fatal("accepted partial bot lists")
	}
}
