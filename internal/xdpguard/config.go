// Package xdpguard implements the optional Linux-only L3/L4 ingress prefilter.
package xdpguard

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
)

type Port struct {
	Protocol string `json:"protocol"`
	Port     uint16 `json:"port"`
}
type Config struct {
	Interface        string   `json:"interface"`
	Mode             string   `json:"mode"`
	Ports            []Port   `json:"ports"`
	BlockCIDRs       []string `json:"block_cidrs"`
	AllowCIDRs       []string `json:"allow_cidrs"`
	PacketsPerSecond uint32   `json:"packets_per_second"`
	SYNsPerSecond    uint32   `json:"syns_per_second"`
	DropFragments    bool     `json:"drop_fragments"`
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
	return nil
}
