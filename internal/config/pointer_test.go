package config

import (
	"sync"
	"testing"
)

func TestPointerLoadStore(t *testing.T) {
	c1 := &Config{PollIntervalSeconds: 5}
	c2 := &Config{PollIntervalSeconds: 9}
	p := NewPointer(c1)
	if p.Load() != c1 {
		t.Error("initial Load mismatch")
	}
	p.Store(c2)
	if p.Load() != c2 {
		t.Error("post-store Load mismatch")
	}
}

func TestPointerConcurrent(t *testing.T) {
	// Tiny smoke test: readers and a writer go in parallel — should not race
	// and the reader always sees a non-nil Config.
	p := NewPointer(&Config{PollIntervalSeconds: 1})
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 1000 {
				if p.Load() == nil {
					t.Error("nil Load")
				}
			}
		})
	}
	wg.Go(func() {
		for i := range 100 {
			p.Store(&Config{PollIntervalSeconds: i + 1})
		}
	})
	wg.Wait()
}

