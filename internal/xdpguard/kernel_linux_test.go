//go:build linux

package xdpguard

import (
	"encoding/binary"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"net/netip"
	"os"
	"testing"
	"time"
)

func ipv4Packet(src string, port uint16, flags byte) []byte {
	b := make([]byte, 14+20+20)
	binary.BigEndian.PutUint16(b[12:14], 0x0800)
	ip := b[14:]
	ip[0] = 0x45
	binary.BigEndian.PutUint16(ip[2:4], 40)
	ip[8] = 64
	ip[9] = 6
	a := netip.MustParseAddr(src).As4()
	copy(ip[12:16], a[:])
	copy(ip[16:20], []byte{192, 0, 2, 1})
	binary.BigEndian.PutUint16(ip[20:22], 12345)
	binary.BigEndian.PutUint16(ip[22:24], port)
	ip[32] = 0x50
	ip[33] = flags
	return b
}
func ipv6Packet(src string, port uint16, extension bool) []byte {
	extra := 0
	if extension {
		extra = 8
	}
	b := make([]byte, 14+40+extra+20)
	binary.BigEndian.PutUint16(b[12:14], 0x86dd)
	ip := b[14:]
	ip[0] = 0x60
	binary.BigEndian.PutUint16(ip[4:6], uint16(extra+20))
	ip[6] = 6
	ip[7] = 64
	a := netip.MustParseAddr(src).As16()
	copy(ip[8:24], a[:])
	if extension {
		ip[6] = 0
		ip[40] = 6
	}
	tcp := ip[40+extra:]
	binary.BigEndian.PutUint16(tcp[2:4], port)
	tcp[12] = 0x50
	tcp[13] = 2
	return b
}
func kernelCollection(t *testing.T, c Config) *ebpf.Collection {
	t.Helper()
	if os.Getenv("FESS_TEST_XDP") != "1" {
		t.Skip("set FESS_TEST_XDP=1 and run with BPF privileges on Linux 5.15+")
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		t.Fatal(err)
	}
	c.Interface = "test0"
	x, err := load(c)
	if err != nil {
		t.Fatalf("kernel verifier: %+v", err)
	}
	t.Cleanup(x.Close)
	return x
}
func action(t *testing.T, c *ebpf.Collection, packet []byte) uint32 {
	t.Helper()
	value, _, err := c.Programs["fess_filter"].Test(packet)
	if err != nil {
		t.Fatal(err)
	}
	return value
}
func TestKernelCIDRAndTransportScope(t *testing.T) {
	c := kernelCollection(t, Config{BlockCIDRs: []string{"203.0.113.0/24", "2001:db8:bad::/48"}, AllowCIDRs: []string{"203.0.113.7/32", "2001:db8:bad::7/128"}})
	for _, tc := range []struct {
		name   string
		packet []byte
		want   uint32
	}{
		{"blocked-v4", ipv4Packet("203.0.113.8", 80, 2), 1},
		{"allowed-v4", ipv4Packet("203.0.113.7", 80, 2), 2},
		{"management-unaffected", ipv4Packet("203.0.113.8", 22, 2), 2},
		{"blocked-v6", ipv6Packet("2001:db8:bad::8", 443, false), 1},
		{"allow-v6", ipv6Packet("2001:db8:bad::7", 443, false), 2},
		{"v6-hop-extension", ipv6Packet("2001:db8:bad::8", 443, true), 1},
		{"unlisted-source", ipv4Packet("198.51.100.2", 80, 2), 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := action(t, c, tc.packet); got != tc.want {
				t.Fatalf("action=%d want=%d", got, tc.want)
			}
		})
	}
	// Double VLAN tags must not bypass CIDR policy.
	b := ipv4Packet("203.0.113.8", 80, 2)
	tagged := append([]byte{}, b[:12]...)
	tagged = append(tagged, 0x88, 0xa8, 0, 1, 0x81, 0, 0, 2, 0x08, 0)
	tagged = append(tagged, b[14:]...)
	if got := action(t, c, tagged); got != 1 {
		t.Fatalf("VLAN bypass: %d", got)
	}
}
func TestKernelRateLimitsAndWindowReset(t *testing.T) {
	for _, tc := range []struct {
		name  string
		cfg   Config
		flags byte
	}{{"packets", Config{PacketsPerSecond: 2}, 0x10}, {"syn", Config{SYNsPerSecond: 2}, 2}} {
		t.Run(tc.name, func(t *testing.T) {
			c := kernelCollection(t, tc.cfg)
			// Align shortly after a monotonic second to avoid crossing the fixed-window
			// boundary between the three packet test calls.
			packet := ipv4Packet("198.51.100.8", 80, tc.flags)
			// All calls ordinarily complete within milliseconds; repeat with a fresh
			// source if a second boundary falls between them.
			var rejected bool
			for attempt := 0; attempt < 3; attempt++ {
				packet[14+15] = byte(10 + attempt)
				first := action(t, c, packet)
				second := action(t, c, packet)
				third := action(t, c, packet)
				if first == 2 && second == 2 && third == 1 {
					rejected = true
					break
				}
			}
			if !rejected {
				t.Fatal("rate budget not enforced")
			}
			time.Sleep(1100 * time.Millisecond)
			if got := action(t, c, packet); got != 2 {
				t.Fatalf("budget did not reset: %d", got)
			}
		})
	}
}
func TestKernelFragments(t *testing.T) {
	packet := ipv4Packet("203.0.113.8", 80, 2)
	binary.BigEndian.PutUint16(packet[14+6:14+8], 0x2000)
	for _, drop := range []bool{false, true} {
		c := kernelCollection(t, Config{DropFragments: drop})
		want := uint32(2)
		if drop {
			want = 1
		}
		if got := action(t, c, packet); got != want {
			t.Fatalf("fragment option=%v action=%d", drop, got)
		}
	}
}
