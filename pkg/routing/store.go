package routing

import (
	"net/url"
	"sync/atomic"
)

type Store struct {
	v atomic.Value // Snapshot
}

func NewStore(defaultUpstream *url.URL) *Store {
	s := &Store{}
	s.v.Store(Snapshot{Default: defaultUpstream})
	return s
}

func (s *Store) Current() Snapshot {
	x := s.v.Load()
	if x == nil {
		return Snapshot{}
	}
	return x.(Snapshot)
}

func (s *Store) Swap(next Snapshot) {
	s.v.Store(next)
}
