package xdpguard

import (
	"context"
	"log"
	"net"
	"net/netip"
	"os"
	"os/user"
	"strconv"
	"sync"
	"time"
)

// Only local processes with write access to the socket can request a ban. The
// wire message is an IP literal; clients cannot select TTL or mutate config.
func listenTemporaryBlocks(ctx context.Context, cfg TemporaryBlockConfig, add func(netip.Addr) error) (func(), error) {
	gid := -1
	if cfg.SocketGroup != "" {
		group, err := user.LookupGroup(cfg.SocketGroup)
		if err != nil {
			return nil, err
		}
		gid, err = strconv.Atoi(group.Gid)
		if err != nil {
			return nil, err
		}
	}
	conn, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: cfg.SocketPath, Net: "unixgram"})
	if err != nil {
		return nil, err
	}
	cleanup := func() { conn.Close(); os.Remove(cfg.SocketPath) }
	mode := os.FileMode(0600)
	if gid >= 0 {
		mode = 0660
		if gid != os.Getegid() {
			err = os.Chown(cfg.SocketPath, -1, gid)
		}
	}
	if err == nil {
		err = os.Chmod(cfg.SocketPath, mode)
	}
	if err != nil {
		cleanup()
		return nil, err
	}
	var once sync.Once
	done, readerDone := make(chan struct{}), make(chan struct{})
	stop := func() {
		once.Do(func() { close(done); cleanup() })
		// The BPF collection must outlive any update already being processed.
		<-readerDone
	}
	go func() {
		select {
		case <-ctx.Done():
			stop()
		case <-done:
		}
	}()
	go func() {
		defer close(readerDone)
		buf := make([]byte, 128)
		var lastError time.Time
		for {
			n, _, err := conn.ReadFromUnix(buf)
			if err != nil {
				return
			}
			ip, err := netip.ParseAddr(string(buf[:n]))
			if err != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
				continue
			}
			if err = add(ip.Unmap()); err != nil && time.Since(lastError) >= 10*time.Second {
				log.Printf("xdp temporary block update failed: %v", err)
				lastError = time.Now()
			}
		}
	}()
	log.Printf("xdp temporary blocks listening socket=%s ttl=%ds", cfg.SocketPath, cfg.TTLSeconds)
	return stop, nil
}
