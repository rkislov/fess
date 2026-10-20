package threatfeed

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

func TestHashSetMatchBody(t *testing.T) {
	body := []byte("test payload")
	sum := sha256.Sum256(body)
	h256 := hex.EncodeToString(sum[:])
	s := NewHashSet([]string{h256})
	if m, ok := s.MatchBody(body); !ok || m != h256 {
		t.Fatalf("match: ok=%v hash=%q", ok, m)
	}
}
