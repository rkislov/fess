package threatfeed

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// HashSet holds normalized MD5/SHA256 hex digests for O(1) lookup.
type HashSet struct {
	m map[string]struct{}
}

func NewHashSet(hashes []string) *HashSet {
	m := make(map[string]struct{}, len(hashes))
	for _, h := range hashes {
		h = NormalizeFileHash(h)
		if h == "" {
			continue
		}
		m[h] = struct{}{}
	}
	if len(m) == 0 {
		return nil
	}
	return &HashSet{m: m}
}

func (s *HashSet) Len() int {
	if s == nil {
		return 0
	}
	return len(s.m)
}

func (s *HashSet) Contains(hash string) bool {
	if s == nil || len(s.m) == 0 {
		return false
	}
	_, ok := s.m[NormalizeFileHash(hash)]
	return ok
}

// MatchBody returns the matched hash hex if body digest is in the set.
func (s *HashSet) MatchBody(body []byte) (matched string, ok bool) {
	if s == nil || len(body) == 0 {
		return "", false
	}
	sum256 := sha256.Sum256(body)
	h256 := hex.EncodeToString(sum256[:])
	if s.Contains(h256) {
		return h256, true
	}
	sum128 := md5.Sum(body)
	h128 := hex.EncodeToString(sum128[:])
	if s.Contains(h128) {
		return h128, true
	}
	return "", false
}

// NormalizeFileHash lowercases and validates MD5 (32) or SHA256 (64) hex.
func NormalizeFileHash(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if !isHexString(s) {
		return ""
	}
	switch len(s) {
	case 32, 64:
		return s
	default:
		return ""
	}
}

func isHexString(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return len(s) > 0
}

// UniqueFileHashes deduplicates normalized hashes.
func UniqueFileHashes(list []string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, h := range list {
		h = NormalizeFileHash(h)
		if h == "" {
			continue
		}
		if _, ok := seen[h]; ok {
			continue
		}
		seen[h] = struct{}{}
		out = append(out, h)
	}
	return out
}
