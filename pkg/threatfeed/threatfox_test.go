package threatfeed

import "testing"

func TestExtractIPsFromThreatFoxIOC(t *testing.T) {
	tests := []struct {
		ioc, typ string
		want     string
	}{
		{"203.0.113.1", "ip", "203.0.113.1"},
		{"172.241.164.247:5655", "ip:port", "172.241.164.247"},
		{"[2001:db8::1]:443", "ip:port", "2001:db8::1"},
		{"evil.example", "domain", ""},
	}
	for _, tc := range tests {
		got := ExtractIPsFromThreatFoxIOC(tc.ioc, tc.typ)
		if tc.want == "" {
			if len(got) != 0 {
				t.Fatalf("%q %q: want empty, got %v", tc.ioc, tc.typ, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Fatalf("%q %q: got %v want [%s]", tc.ioc, tc.typ, got, tc.want)
		}
	}
}

func TestExtractHashFromThreatFoxIOC(t *testing.T) {
	h := ExtractHashFromThreatFoxIOC("3941d2e13d9ed19d7f867bd266338e9ec0c8eb986ff656743c83c6d1a03555cc", "sha256_hash")
	if len(h) != 64 {
		t.Fatalf("sha256: got %q", h)
	}
	h = ExtractHashFromThreatFoxIOC("2151c4b970eff0071948dbbc19066aa4", "md5_hash")
	if len(h) != 32 {
		t.Fatalf("md5: got %q", h)
	}
}

func TestParseThreatFoxAPIHashes(t *testing.T) {
	body := []byte(`{
	  "query_status": "ok",
	  "data": [
	    {"ioc": "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef", "ioc_type": "sha256_hash"},
	    {"ioc": "198.51.100.8", "ioc_type": "ip"}
	  ]
	}`)
	p, err := ParseThreatFoxAPI(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Hashes) != 1 || len(p.IPs) != 1 {
		t.Fatalf("got hashes=%d ips=%d", len(p.Hashes), len(p.IPs))
	}
}

func TestIPsFromThreatFoxAPI(t *testing.T) {
	body := []byte(`{
	  "query_status": "ok",
	  "data": [
	    {"ioc": "198.51.100.8", "ioc_type": "ip"},
	    {"ioc": "10.0.0.5:8080", "ioc_type": "ip:port"},
	    {"ioc": "bad.test", "ioc_type": "domain"}
	  ]
	}`)
	ips, err := IPsFromThreatFoxAPI(body)
	if err != nil {
		t.Fatal(err)
	}
	if len(ips) != 2 {
		t.Fatalf("got %v", ips)
	}
}
