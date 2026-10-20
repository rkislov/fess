package policy

import "sync/atomic"

type Store struct {
	active atomic.Value
}

func NewStore() *Store {
	s := &Store{}
	s.active.Store(Snapshot{Version: 0})
	return s
}

func (s *Store) Current() Snapshot {
	return s.active.Load().(Snapshot)
}

func (s *Store) Swap(next Snapshot) {
	s.active.Store(next)
}
