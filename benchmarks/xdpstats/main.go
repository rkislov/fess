//go:build linux

// xdpstats reads the single disposable benchmark counters map without modifying it.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/cilium/ebpf"
	"os"
)

func main() {
	var id ebpf.MapID
	var found *ebpf.Map
	for {
		next, err := ebpf.MapGetNextID(id)
		if err != nil {
			break
		}
		id = next
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			continue
		}
		info, err := m.Info()
		if err == nil && info.Name == "counters" {
			if found != nil {
				panic("ambiguous counters maps")
			}
			found = m
		} else {
			m.Close()
		}
	}
	if found == nil {
		panic("counters map missing")
	}
	defer found.Close()
	result := map[string]uint64{}
	for k, name := range []string{"seen", "passed", "cidr_drop", "rate_drop", "fragment_drop", "malformed_pass"} {
		key := uint32(k)
		var values []uint64
		if err := found.Lookup(&key, &values); err != nil {
			panic(err)
		}
		for _, v := range values {
			result[name] += v
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		panic(fmt.Sprint(err))
	}
}
