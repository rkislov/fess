// Package xdpguard implements the optional Linux-only L3/L4 ingress prefilter.
package xdpguard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
)

type Port struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}

// BudgetConfig applies one shared token bucket to all configured TCP/UDP ports.
// A zero rate disables that dimension; burst is measured in packets or bytes.
type BudgetConfig struct {
	Enabled          bool   `json:"enabled"`
	PacketsPerSecond uint32 `json:"packets_per_second"`
	PacketBurst      uint32 `json:"packet_burst"`
	BytesPerSecond   uint32 `json:"bytes_per_second"`
	ByteBurst        uint32 `json:"byte_burst"`
	SYNsPerSecond    uint32 `json:"syns_per_second"`
	SYNBurst         uint32 `json:"syn_burst"`
}
type ICMPConfig struct {
	Enabled               bool   `json:"enabled"`
	PacketsPerSecond      uint32 `json:"packets_per_second"`
	Burst                 uint32 `json:"burst"`
	PerIPPacketsPerSecond uint32 `json:"per_ip_packets_per_second"`
	PerIPBurst            uint32 `json:"per_ip_burst"`
}
type MalformedConfig struct {
	Enabled         bool `json:"enabled"`
	InvalidLengths  bool `json:"invalid_lengths"`
	InvalidTCPFlags bool `json:"invalid_tcp_flags"`
}
type TemporaryBlockConfig struct {
	Enabled     bool   `json:"enabled"`
	SocketPath  string `json:"socket_path"`
	SocketGroup string `json:"socket_group"`
	TTLSeconds  uint32 `json:"ttl_seconds"`
}

type Config struct {
	Interface        string               `json:"interface"`
	Mode             string               `json:"mode"`
	Ports            []Port               `json:"ports"`
	BlockCIDRs       []string             `json:"block_cidrs"`
	AllowCIDRs       []string             `json:"allow_cidrs"`
	PacketsPerSecond uint32               `json:"packets_per_second"`
	SYNsPerSecond    uint32               `json:"syns_per_second"`
	DropFragments    bool                 `json:"drop_fragments"`
	GlobalBudget     BudgetConfig         `json:"global_budget"`
	ICMPPing         ICMPConfig           `json:"icmp_ping"`
	MalformedPackets MalformedConfig      `json:"malformed_packets"`
	TemporaryBlocks  TemporaryBlockConfig `json:"temporary_blocks"`
}

func ReadConfig(path string) (Config, error) {
	var c Config
	f, err := os.Open(path)
	if err != nil {
		return c, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 4<<20))
	d.DisallowUnknownFields()
	if err = d.Decode(&c); err != nil {
		return c, err
	}
	var extra any
	if err = d.Decode(&extra); err != io.EOF {
		return c, fmt.Errorf("expected one JSON object")
	}
	return c, c.Validate()
}
func (c *Config) Validate() error {
	if c.Interface == "" {
		return fmt.Errorf("interface must be explicitly configured")
	}
	if c.Mode == "" {
		c.Mode = "native"
	}
	if c.Mode != "native" && c.Mode != "generic" {
		return fmt.Errorf("mode must be native or generic")
	}
	if c.Ports == nil {
		c.Ports = []Port{{"tcp", 80}, {"tcp", 443}}
	}
	if len(c.Ports) == 0 || len(c.Ports) > 4096 {
		return fmt.Errorf("configure 1..4096 protected ports")
	}
	for _, p := range c.Ports {
		if p.Port == 0 || (p.Protocol != "tcp" && p.Protocol != "udp") {
			return fmt.Errorf("invalid protected port: %+v", p)
		}
	}
	for _, list := range [][]string{c.BlockCIDRs, c.AllowCIDRs} {
		if len(list) > 16384 {
			return fmt.Errorf("CIDR list too large")
		}
		for _, s := range list {
			p, err := netip.ParsePrefix(s)
			if err != nil || p.Addr().Is4In6() {
				return fmt.Errorf("invalid CIDR %q", s)
			}
		}
	}
	if c.PacketsPerSecond > 1000000000 || c.SYNsPerSecond > 1000000000 {
		return fmt.Errorf("rate limits must not exceed 1000000000")
	}

	for _, pair := range []struct {
		name        string
		rate, burst uint32
	}{
		{"global packets", c.GlobalBudget.PacketsPerSecond, c.GlobalBudget.PacketBurst},
		{"global bytes", c.GlobalBudget.BytesPerSecond, c.GlobalBudget.ByteBurst},
		{"global SYNs", c.GlobalBudget.SYNsPerSecond, c.GlobalBudget.SYNBurst},
		{"ICMP global", c.ICMPPing.PacketsPerSecond, c.ICMPPing.Burst},
		{"ICMP per IP", c.ICMPPing.PerIPPacketsPerSecond, c.ICMPPing.PerIPBurst},
	} {
		if pair.rate > 1000000000 || pair.burst > 1000000000 {
			return fmt.Errorf("%s rate/burst must not exceed 1000000000", pair.name)
		}
		if (pair.rate == 0) != (pair.burst == 0) {
			return fmt.Errorf("%s: rate and burst must both be zero or positive", pair.name)
		}
	}
	if c.GlobalBudget.Enabled && c.GlobalBudget.PacketsPerSecond == 0 && c.GlobalBudget.BytesPerSecond == 0 && c.GlobalBudget.SYNsPerSecond == 0 {
		return fmt.Errorf("global_budget requires at least one rate")
	}
	if c.ICMPPing.Enabled && c.ICMPPing.PacketsPerSecond == 0 && c.ICMPPing.PerIPPacketsPerSecond == 0 {
		return fmt.Errorf("icmp_ping requires at least one rate")
	}
	if c.MalformedPackets.Enabled && !c.MalformedPackets.InvalidLengths && !c.MalformedPackets.InvalidTCPFlags {
		return fmt.Errorf("malformed_packets requires at least one check")
	}
	if c.TemporaryBlocks.Enabled {
		if !filepath.IsAbs(c.TemporaryBlocks.SocketPath) || len(c.TemporaryBlocks.SocketPath) > 100 {
			return fmt.Errorf("temporary_blocks.socket_path must be an absolute Unix socket path of at most 100 bytes")
		}
		if c.TemporaryBlocks.TTLSeconds == 0 || c.TemporaryBlocks.TTLSeconds > 86400 {
			return fmt.Errorf("temporary_blocks.ttl_seconds must be 1..86400")
		}
	}
	return nil
}
