package tlssites

import (
	"context"
	"crypto/tls"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"fence/pkg/routing"
)

// Snapshot holds TLS keypairs keyed by site host_pattern order for SNI selection.
type Snapshot struct {
	// Entries in routing priority order (same ORDER BY as LoadSnapshot query).
	Entries []Entry
}

// Entry is one site TLS certificate with its host pattern for SNI matching.
type Entry struct {
	HostPattern string
	Cert        tls.Certificate
}

// Store is an atomic TLS credential snapshot for the gateway.
type Store struct {
	mu   sync.RWMutex
	snap Snapshot
}

func (s *Store) Swap(next Snapshot) {
	s.mu.Lock()
	s.snap = next
	s.mu.Unlock()
}

// Current returns the latest snapshot (copy safe for read-only iteration).
func (s *Store) Current() Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.snap
}

// GetCertificate implements tls.Config.GetCertificate.
func (s *Store) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	sni := strings.TrimSpace(strings.ToLower(hello.ServerName))
	snap := s.Current()
	if sni == "" && len(snap.Entries) == 1 {
		c := snap.Entries[0].Cert
		return &c, nil
	}
	for _, e := range snap.Entries {
		if routing.HostMatch(e.HostPattern, sni) {
			c := e.Cert
			return &c, nil
		}
	}
	return nil, fmt.Errorf("no tls certificate for server name %q", sni)
}

// LoadSnapshot reads sites that have TLS enabled and non-empty PEM material.
func LoadSnapshot(ctx context.Context, db *sql.DB) (Snapshot, error) {
	var out Snapshot
	rows, err := db.QueryContext(ctx, `
SELECT s.host_pattern,
  COALESCE(NULLIF(trim(c.cert_pem), ''), COALESCE(s.tls_cert_pem, '')),
  COALESCE(NULLIF(trim(c.key_pem), ''), COALESCE(s.tls_key_pem, ''))
FROM sites s
LEFT JOIN certificates c ON c.id = s.certificate_id
WHERE s.enabled = TRUE
  AND s.tls_enabled = TRUE
  AND (
    (length(trim(COALESCE(c.cert_pem, ''))) > 0 AND length(trim(COALESCE(c.key_pem, ''))) > 0)
    OR (length(trim(COALESCE(s.tls_cert_pem, ''))) > 0 AND length(trim(COALESCE(s.tls_key_pem, ''))) > 0)
  )
ORDER BY s.priority ASC, s.created_at ASC`)
	if err != nil {
		return out, fmt.Errorf("tls sites query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var pat, certPEM, keyPEM string
		if err := rows.Scan(&pat, &certPEM, &keyPEM); err != nil {
			return out, err
		}
		cert, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
		if err != nil {
			return out, fmt.Errorf("tls X509KeyPair for pattern %q: %w", pat, err)
		}
		out.Entries = append(out.Entries, Entry{HostPattern: strings.TrimSpace(pat), Cert: cert})
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	return out, nil
}
