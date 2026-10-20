package routing

import "testing"

func TestClientIPAllowedPrivate(t *testing.T) {
	t.Parallel()
	if !ClientIPAllowed("10.1.2.3", IPAllowPrivate, nil) {
		t.Fatal("10.x should be private")
	}
	if !ClientIPAllowed("192.168.0.1", IPAllowPrivate, nil) {
		t.Fatal("192.168.x should be private")
	}
	if ClientIPAllowed("8.8.8.8", IPAllowPrivate, nil) {
		t.Fatal("8.8.8.8 should be denied")
	}
	if ClientIPAllowed("8.8.8.8", IPAllowNone, nil) {
		return
	}
	t.Fatal("none mode should allow public")
}

func TestClientIPAllowedCustom(t *testing.T) {
	t.Parallel()
	pfx, err := ParsePrefixList([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if !ClientIPAllowed("203.0.113.42", IPAllowCustom, pfx) {
		t.Fatal("expected allow in custom CIDR")
	}
	if ClientIPAllowed("1.2.3.4", IPAllowCustom, pfx) {
		t.Fatal("expected deny outside CIDR")
	}
}
