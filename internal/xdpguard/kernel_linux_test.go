//go:build linux

package xdpguard

import (
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
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

func TestKernelUDPPortScope(t *testing.T) {
	c := kernelCollection(t, Config{Ports: []Port{{"udp", 443}}, BlockCIDRs: []string{"203.0.113.0/24"}})
	packet := ipv4Packet("203.0.113.8", 443, 0)
	packet = packet[:14+20+8]
	packet[14+9] = 17
	binary.BigEndian.PutUint16(packet[14+2:14+4], 28)
	binary.BigEndian.PutUint16(packet[14+20+4:14+20+6], 8)
	if got := action(t, c, packet); got != 1 {
		t.Fatalf("UDP protected port bypass: %d", got)
	}
	binary.BigEndian.PutUint16(packet[14+20+2:14+20+4], 53)
	if got := action(t, c, packet); got != 2 {
		t.Fatalf("unprotected UDP affected: %d", got)
	}
	if got := action(t, c, ipv4Packet("203.0.113.8", 443, 2)); got != 2 {
		t.Fatalf("UDP-only configuration affected TCP: %d", got)
	}
}

func icmpPacket(v6 bool, src string, kind byte) []byte {
	var b []byte
	if v6 {
		b = ipv6Packet(src, 0, false)[:14+40+8]
		b[14+6] = 58
		binary.BigEndian.PutUint16(b[14+4:], 8)
		clear(b[14+40:])
		b[14+40] = kind
	} else {
		b = ipv4Packet(src, 0, 0)[:14+20+8]
		b[14+9] = 1
		binary.BigEndian.PutUint16(b[14+2:], 28)
		clear(b[14+20:])
		b[14+20] = kind
	}
	return b
}

func TestKernelGlobalBudgets(t *testing.T) {
	for _, dimension := range []string{"packets", "bytes", "syns"} {
		t.Run(dimension, func(t *testing.T) {
			b := BudgetConfig{Enabled: true}
			switch dimension {
			case "packets":
				b.PacketsPerSecond, b.PacketBurst = 1, 2
			case "bytes":
				b.BytesPerSecond, b.ByteBurst = 1, 128 // IPv4 54 + IPv6 74 bytes
			case "syns":
				b.SYNsPerSecond, b.SYNBurst = 1, 2
			}
			c := kernelCollection(t, Config{GlobalBudget: b, AllowCIDRs: []string{"192.0.2.9/32"}})
			// Different sources/families share one non-evictable aggregate budget.
			for _, packet := range [][]byte{ipv4Packet("198.51.100.1", 80, 2), ipv6Packet("2001:db8::2", 443, false)} {
				if got := action(t, c, packet); got != 2 {
					t.Fatalf("initial burst rejected: %d", got)
				}
			}
			if got := action(t, c, ipv4Packet("198.51.100.3", 80, 2)); got != 1 {
				t.Fatalf("aggregate limit bypassed: %d", got)
			}
			for _, packet := range [][]byte{ipv4Packet("198.51.100.3", 22, 2), ipv4Packet("192.0.2.9", 80, 2), icmpPacket(false, "198.51.100.3", 8)} {
				if got := action(t, c, packet); got != 2 {
					t.Fatalf("unrelated/allowed traffic affected: %d", got)
				}
			}
			if dimension == "syns" && action(t, c, ipv4Packet("198.51.100.3", 80, 0x10)) != 2 {
				t.Fatal("SYN-only budget affected ACK")
			}
		})
	}
	c := kernelCollection(t, Config{GlobalBudget: BudgetConfig{Enabled: true, PacketsPerSecond: 10, PacketBurst: 1}})
	p := ipv4Packet("198.51.100.8", 80, 2)
	if action(t, c, p) != 2 || action(t, c, p) != 1 {
		t.Fatal("initial token budget")
	}
	time.Sleep(150 * time.Millisecond)
	if action(t, c, p) != 2 {
		t.Fatal("token budget did not refill")
	}
}

func TestKernelICMPPing(t *testing.T) {
	for _, v6 := range []bool{false, true} {
		for _, global := range []bool{false, true} {
			t.Run(fmt.Sprintf("v6=%v/global=%v", v6, global), func(t *testing.T) {
				cfg := ICMPConfig{Enabled: true}
				if global {
					cfg.PacketsPerSecond, cfg.Burst = 1, 2
				} else {
					cfg.PerIPPacketsPerSecond, cfg.PerIPBurst = 1, 2
				}
				c := kernelCollection(t, Config{ICMPPing: cfg, AllowCIDRs: []string{"192.0.2.9/32", "2001:db8::9/128"}})
				src, other, allow := "198.51.100.1", "198.51.100.2", "192.0.2.9"
				kind := byte(8)
				if v6 {
					src, other, allow = "2001:db8::1", "2001:db8::2", "2001:db8::9"
					kind = 128
				}
				p := icmpPacket(v6, src, kind)
				if action(t, c, p) != 2 || action(t, c, p) != 2 || action(t, c, p) != 1 {
					t.Fatal("echo budget not enforced")
				}
				want := uint32(2)
				if global {
					want = 1
				}
				if got := action(t, c, icmpPacket(v6, other, kind)); got != want {
					t.Fatalf("second source: %d want %d", got, want)
				}
				if action(t, c, icmpPacket(v6, allow, kind)) != 2 {
					t.Fatal("allow CIDR affected")
				}
				kinds := []byte{0, 3, 11}
				if v6 {
					kinds = []byte{129, 1, 2, 3, 4, 133, 134, 135, 136}
				}
				for _, k := range kinds {
					if action(t, c, icmpPacket(v6, src, k)) != 2 {
						t.Fatalf("essential/non-echo ICMP type %d affected", k)
					}
				}
				if action(t, c, ipv4Packet("198.51.100.1", 80, 2)) != 2 {
					t.Fatal("TCP affected by ICMP budget")
				}
			})
		}
	}
	// Omitted/disabled settings retain previous behavior.
	c := kernelCollection(t, Config{ICMPPing: ICMPConfig{PacketsPerSecond: 1, Burst: 1}})
	for i := 0; i < 3; i++ {
		if action(t, c, icmpPacket(false, "198.51.100.1", 8)) != 2 {
			t.Fatal("disabled ICMP filter active")
		}
	}
}

func TestKernelMalformedPackets(t *testing.T) {
	cases := []struct {
		name   string
		packet []byte
	}{
		{"tcp-offset", ipv4Packet("198.51.100.1", 80, 2)},
		{"syn-fin", ipv4Packet("198.51.100.1", 80, 3)},
		{"syn-rst", ipv4Packet("198.51.100.1", 80, 6)},
		{"ip-length", ipv4Packet("198.51.100.1", 80, 2)},
		{"short-tcp", ipv4Packet("198.51.100.1", 80, 2)[:14+20+8]},
		{"v6-length", ipv6Packet("2001:db8::1", 443, true)},
		{"udp-length", ipv4Packet("198.51.100.1", 80, 0)[:14+20+8]},
	}
	cases[0].packet[14+20+12] = 0x40
	binary.BigEndian.PutUint16(cases[3].packet[14+2:], 100)
	binary.BigEndian.PutUint16(cases[4].packet[14+2:], 28)
	binary.BigEndian.PutUint16(cases[5].packet[14+4:], 200)
	cases[6].packet[14+9] = 17
	binary.BigEndian.PutUint16(cases[6].packet[14+2:], 28)
	binary.BigEndian.PutUint16(cases[6].packet[14+20+4:], 100)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, enabled := range []bool{false, true} {
				c := kernelCollection(t, Config{Ports: []Port{{"tcp", 80}, {"tcp", 443}, {"udp", 80}}, MalformedPackets: MalformedConfig{Enabled: enabled, InvalidLengths: true, InvalidTCPFlags: true}})
				want := uint32(2)
				if enabled {
					want = 1
				}
				if got := action(t, c, tc.packet); got != want {
					t.Fatalf("enabled=%v got=%d want=%d", enabled, got, want)
				}
			}
		})
	}
	c := kernelCollection(t, Config{MalformedPackets: MalformedConfig{Enabled: true, InvalidLengths: true, InvalidTCPFlags: true}})
	for _, p := range [][]byte{ipv4Packet("198.51.100.1", 80, 2), ipv6Packet("2001:db8::1", 443, true), ipv4Packet("198.51.100.1", 22, 3), icmpPacket(true, "2001:db8::1", 2), make([]byte, 14)} {
		if action(t, c, p) != 2 {
			t.Fatal("valid or unscoped traffic affected")
		}
	}
	// Ethernet padding is not part of the IP/TCP payload length.
	padded := append(ipv4Packet("198.51.100.1", 80, 2), make([]byte, 20)...)
	if action(t, c, padded) != 2 {
		t.Fatal("Ethernet padding affected length checks")
	}
	// Checks are independently selectable.
	c = kernelCollection(t, Config{MalformedPackets: MalformedConfig{Enabled: true, InvalidLengths: true}})
	if action(t, c, cases[1].packet) != 2 {
		t.Fatal("disabled TCP flag check active")
	}
	c = kernelCollection(t, Config{MalformedPackets: MalformedConfig{Enabled: true, InvalidTCPFlags: true}})
	if action(t, c, cases[0].packet) != 2 {
		t.Fatal("disabled TCP length check active")
	}
}

func TestKernelTemporaryBans(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		cfg := TemporaryBlockConfig{Enabled: enabled, SocketPath: "/run/fess-xdp/blocks.sock", TTLSeconds: 1}
		c := kernelCollection(t, Config{TemporaryBlocks: cfg, AllowCIDRs: []string{"192.0.2.9/32"}})
		for _, src := range []string{"198.51.100.1", "2001:db8::1", "192.0.2.9"} {
			if err := addTemporaryBan(c.Maps["temporary_bans"], netip.MustParseAddr(src), 1); err != nil {
				t.Fatal(err)
			}
		}
		for _, p := range [][]byte{ipv4Packet("198.51.100.1", 80, 2), ipv6Packet("2001:db8::1", 443, false)} {
			want := uint32(2)
			if enabled {
				want = 1
			}
			if got := action(t, c, p); got != want {
				t.Fatalf("enabled=%v ban action=%d", enabled, got)
			}
		}
		for _, p := range [][]byte{ipv4Packet("198.51.100.1", 22, 2), ipv4Packet("192.0.2.9", 80, 2), icmpPacket(false, "198.51.100.1", 8)} {
			if action(t, c, p) != 2 {
				t.Fatal("ban affected unprotected/allowed traffic")
			}
		}
		if enabled {
			time.Sleep(1100 * time.Millisecond)
			if action(t, c, ipv4Packet("198.51.100.1", 80, 2)) != 2 {
				t.Fatal("ban did not expire")
			}
		}
	}
}

func TestKernelGlobalBudgetAcrossConcurrentCPUs(t *testing.T) {
	c := kernelCollection(t, Config{GlobalBudget: BudgetConfig{Enabled: true, PacketsPerSecond: 1, PacketBurst: 20}})
	var passed atomic.Uint32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			p := ipv4Packet(fmt.Sprintf("198.51.100.%d", i+1), 80, 2)
			v, _, err := c.Programs["fess_filter"].Test(p)
			if err != nil {
				t.Error(err)
				return
			}
			if v == 2 {
				passed.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := passed.Load(); got != 20 {
		t.Fatalf("shared budget allowed %d packets; want 20", got)
	}
}

func TestKernelValidUDPWithTrailingIPPadding(t *testing.T) {
	c := kernelCollection(t, Config{Ports: []Port{{"udp", 443}}, MalformedPackets: MalformedConfig{Enabled: true, InvalidLengths: true}})
	p := ipv4Packet("198.51.100.1", 443, 0)
	p[14+9] = 17
	// The UDP length bounds its own datagram; extra IP payload is not an
	// out-of-bounds UDP length and must not be classified as malformed.
	binary.BigEndian.PutUint16(p[14+20+4:], 8)
	if action(t, c, p) != 2 {
		t.Fatal("valid UDP length with trailing IP padding rejected")
	}
}

func TestKernelTrafficCounters(t *testing.T) {
	c := kernelCollection(t, Config{})
	tcp := ipv4Packet("198.51.100.1", 80, 2)
	echo := icmpPacket(false, "198.51.100.2", 8)
	if action(t, c, tcp) != 2 || action(t, c, echo) != 2 {
		t.Fatal("counter instrumentation changed packet decisions")
	}
	stats, err := readCounters(c)
	if err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]uint64{"seen": 2, "passed": 2, "protected_packets": 1, "protected_syn": 1, "icmp_echo": 1, "frame_bytes": uint64(len(tcp) + len(echo)), "protected_bytes": uint64(len(tcp))} {
		if stats[key] != want {
			t.Fatalf("%s=%d want=%d", key, stats[key], want)
		}
	}
}
