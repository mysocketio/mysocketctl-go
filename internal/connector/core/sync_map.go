package core

import "sync"

type SyncMap struct {
	mutex sync.Mutex
	m     sync.Map
}

func NewSyncMap() *SyncMap {
	return &SyncMap{m: sync.Map{}}
}

func (s *SyncMap) Add(key, value interface{}) {
	s.mutex.Lock()
	s.m.Store(key, value)
	s.mutex.Unlock()
}

func (s *SyncMap) Get(key interface{}) (interface{}, bool) {
	value, ok := s.m.Load(key)
	return value, ok
}

func (s *SyncMap) Delete(key interface{}) {
	s.mutex.Lock()
	s.m.Delete(key)
	s.mutex.Unlock()
}

func (s *SyncMap) Len() int {
	count := 0
	s.m.Range(func(k, v interface{}) bool {
		count++
		return true
	})

	return count
}
