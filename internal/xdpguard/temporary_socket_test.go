package xdpguard

import (
	"context"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestTemporaryBlockSocket(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	path := filepath.Join(t.TempDir(), "b.sock")
	added := make(chan netip.Addr, 4)
	stop, err := listenTemporaryBlocks(ctx, TemporaryBlockConfig{SocketPath: path, TTLSeconds: 60}, func(ip netip.Addr) error { added <- ip; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0600 {
		t.Fatalf("socket mode: %v", st.Mode())
	}
	conn, err := net.Dial("unixgram", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for _, raw := range []string{"not an IP", "0.0.0.0", "ff02::1", "fe80::1%eth0", "198.51.100.2 extra", "::ffff:198.51.100.2", "2001:db8::1"} {
		if _, err := conn.Write([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, want := range []string{"198.51.100.2", "2001:db8::1"} {
		select {
		case ip := <-added:
			if ip.String() != want {
				t.Fatalf("got %s want %s", ip, want)
			}
		case <-time.After(time.Second):
			t.Fatal("no ban callback")
		}
	}
	select {
	case ip := <-added:
		t.Fatalf("unexpected ban: %s", ip)
	default:
	}
	stop()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("socket not removed: %v", err)
	}
}

func TestTemporarySocketDoesNotReplaceExistingPath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(path, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := listenTemporaryBlocks(context.Background(), TemporaryBlockConfig{SocketPath: path}, func(netip.Addr) error { return nil })
	if err == nil {
		t.Fatal("replaced existing path")
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != "keep" {
		t.Fatal("existing path changed")
	}
}

func TestBanThresholdSocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.sock")
	added := make(chan netip.Addr, 2)
	stop, err := listenTemporaryBlocks(context.Background(), TemporaryBlockConfig{SocketPath: path, MinEvents: 3, WindowSeconds: 30}, func(ip netip.Addr) error { added <- ip; return nil })
	if err != nil {
		t.Fatal(err)
	}
	defer stop()
	conn, err := net.Dial("unixgram", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	for i := 0; i < 2; i++ {
		if _, err := conn.Write([]byte("198.51.100.1")); err != nil {
			t.Fatal(err)
		}
	}
	select {
	case <-added:
		t.Fatal("single/second violation caused a packet ban")
	case <-time.After(30 * time.Millisecond):
	}
	if _, err := conn.Write([]byte("198.51.100.1")); err != nil {
		t.Fatal(err)
	}
	select {
	case ip := <-added:
		if ip.String() != "198.51.100.1" {
			t.Fatal(ip)
		}
	case <-time.After(time.Second):
		t.Fatal("threshold did not create a ban")
	}
}
