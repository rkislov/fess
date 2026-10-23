//go:build linux

package xdpguard

import (
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
	"net/netip"
)

type sourceKey struct {
	Family uint32
	Addr   [16]byte
}

func sourceFor(ip netip.Addr) sourceKey {
	ip = ip.Unmap()
	k := sourceKey{Family: 6, Addr: ip.As16()}
	if ip.Is4() {
		k = sourceKey{Family: 4}
		a := ip.As4()
		copy(k.Addr[:], a[:])
	}
	return k
}

func addTemporaryBan(m *ebpf.Map, ip netip.Addr, ttl uint32) error {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return err
	}
	until := uint64(ts.Nano()) + uint64(ttl)*1000000000
	key := sourceFor(ip)
	return m.Update(&key, &until, ebpf.UpdateAny)
}
