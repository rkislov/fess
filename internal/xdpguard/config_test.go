package xdpguard

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfigValidation(t *testing.T) {
	valid := Config{Interface: "test0", BlockCIDRs: []string{"192.0.2.0/24", "2001:db8::/32"}}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(valid.Ports) != 2 || valid.Mode != "native" {
		t.Fatalf("wrong defaults: %+v", valid)
	}
	for _, cfg := range []Config{{}, {Interface: "test0", Mode: "automatic"}, {Interface: "test0", Ports: []Port{}}, {Interface: "test0", Ports: []Port{{"icmp", 80}}}, {Interface: "test0", BlockCIDRs: []string{"::ffff:192.0.2.1/128"}}, {Interface: "test0", PacketsPerSecond: 1000000001}} {
		if err := cfg.Validate(); err == nil {
			t.Fatalf("accepted invalid config: %+v", cfg)
		}
	}
	path := filepath.Join(t.TempDir(), "xdp.json")
	os.WriteFile(path, []byte(`{"interface":"test0","typo":true}`), 0600)
	if _, err := ReadConfig(path); err == nil {
		t.Fatal("unknown fields must fail")
	}
}
