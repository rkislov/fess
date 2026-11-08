package routing

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"net/http"
	"regexp"
	"slices"
	"sort"
	"sync/atomic"
)

type BalanceConfig struct {
	Mode string `json:"mode"`
	Key  string `json:"key,omitempty"`
}

var httpToken = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}$")

func (c BalanceConfig) Validate() error {
	switch c.Mode {
	case "priority", "round_robin", "ip_hash", "path_hash":
		if c.Key != "" {
			return fmt.Errorf("имя ключа применяется только для хеширования по заголовку или cookie")
		}
	case "header_hash", "cookie_hash":
		if !httpToken.MatchString(c.Key) {
			return fmt.Errorf("укажите допустимое имя HTTP-заголовка или cookie длиной до 128 символов")
		}
	default:
		return fmt.Errorf("неизвестный режим распределения между upstream %q", c.Mode)
	}
	return nil
}

type backendPool struct {
	prefix string
	peers  []*ResolvedBackend
	next   atomic.Uint64
}

func (b *ResolvedBackend) identity() string {
	if b.ID != "" {
		return b.ID
	}
	return b.Backend.String()
}

// Build one pool per normalized prefix, keeping only peers at its best priority.
// Preserve snapshot order for the traditional first-backend policy.
func (s *ResolvedSite) buildPools() {
	byPrefix := make(map[string]*backendPool)
	for i := range s.Backends {
		b := &s.Backends[i]
		if b.Backend == nil {
			continue
		}
		prefix := NormalizePathPrefix(b.PathPrefix)
		if IsCatchAllPath(prefix) {
			prefix = ""
		}
		pool := byPrefix[prefix]
		if pool == nil {
			pool = &backendPool{prefix: prefix}
			byPrefix[prefix] = pool
			s.pools = append(s.pools, pool)
		}
		if len(pool.peers) > 0 {
			first := pool.peers[0]
			switch {
			case b.PathPriority < first.PathPriority || b.PathPriority == first.PathPriority && b.BackendPriority < first.BackendPriority:
				pool.peers = pool.peers[:0]
			case b.PathPriority != first.PathPriority || b.BackendPriority != first.BackendPriority:
				continue
			}
		}
		// Legacy "/", "*" and empty catch-all rows may belong to the same backend.
		if slices.ContainsFunc(pool.peers, func(peer *ResolvedBackend) bool { return peer.identity() == b.identity() }) {
			continue
		}
		pool.peers = append(pool.peers, b)
	}
	sort.SliceStable(s.pools, func(i, j int) bool { return len(s.pools[i].prefix) > len(s.pools[j].prefix) })
}

func (c BalanceConfig) hashKey(r *http.Request, path, clientIP string) string {
	switch c.Mode {
	case "path_hash":
		return path
	case "header_hash":
		if r != nil {
			if value := r.Header.Get(c.Key); value != "" {
				return value
			}
			if http.CanonicalHeaderKey(c.Key) == "Host" && r.Host != "" {
				return r.Host
			}
		}
	case "cookie_hash":
		if r != nil {
			if cookie, err := r.Cookie(c.Key); err == nil && cookie.Value != "" {
				return cookie.Value
			}
		}
	}
	return clientIP
}

// Rendezvous hashing keeps assignments to surviving peers stable when peers change.
func (pool *backendPool) choose(c BalanceConfig, r *http.Request, path, clientIP string) *ResolvedBackend {
	best := pool.peers[0]
	if len(pool.peers) == 1 || c.Mode == "" || c.Mode == "priority" {
		return best
	}
	if c.Mode == "round_robin" {
		return pool.peers[(pool.next.Add(1)-1)%uint64(len(pool.peers))]
	}
	key := sha256.Sum256([]byte(c.hashKey(r, path, clientIP)))
	var highest uint64
	for i, peer := range pool.peers {
		sum := sha256.Sum256(append(key[:], peer.identity()...))
		score := binary.BigEndian.Uint64(sum[:8])
		if i == 0 || score > highest || score == highest && peer.identity() < best.identity() {
			best, highest = peer, score
		}
	}
	return best
}
