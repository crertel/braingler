package config

import (
	"strings"
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

func TestReloadCompatibleAllowsBenignChanges(t *testing.T) {
	prev := &Config{
		Listen:              Listen{Address: "127.0.0.1:8080"},
		PollIntervalSeconds: 5,
	}
	next := &Config{
		Listen:              Listen{Address: "127.0.0.1:8080"},
		PollIntervalSeconds: 9, // changed
	}
	if err := ReloadCompatible(prev, next); err != nil {
		t.Errorf("benign change rejected: %v", err)
	}
}

func TestReloadCompatibleRefusesListen(t *testing.T) {
	prev := &Config{Listen: Listen{Address: "127.0.0.1:8080"}}
	next := &Config{Listen: Listen{Address: "127.0.0.1:9090"}}
	err := ReloadCompatible(prev, next)
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Errorf("listen change should be refused, got: %v", err)
	}
}

func TestReloadCompatibleRefusesSSHCAPaths(t *testing.T) {
	prev := &Config{
		Listen: Listen{Address: "x"},
		SSHCA:  SSHCA{Enabled: true, KeyFile: "/a"},
	}
	next := &Config{
		Listen: Listen{Address: "x"},
		SSHCA:  SSHCA{Enabled: true, KeyFile: "/b"},
	}
	if err := ReloadCompatible(prev, next); err == nil ||
		!strings.Contains(err.Error(), "ssh_ca.key_file") {
		t.Errorf("ssh_ca.key_file change should be refused, got: %v", err)
	}
}

func TestReloadCompatibleRefusesEnableToggle(t *testing.T) {
	prev := &Config{Listen: Listen{Address: "x"}, SSHCA: SSHCA{Enabled: false}}
	next := &Config{Listen: Listen{Address: "x"}, SSHCA: SSHCA{Enabled: true, KeyFile: "/a"}}
	if err := ReloadCompatible(prev, next); err == nil ||
		!strings.Contains(err.Error(), "ssh_ca.enabled") {
		t.Errorf("ssh_ca.enabled toggle should be refused, got: %v", err)
	}
}

