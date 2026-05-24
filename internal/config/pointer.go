package config

import "sync/atomic"

// Pointer wraps an atomic *Config so components can pick up SIGHUP-style
// reloads without locking. Components hold a *Pointer and call Load() on
// each operation; mutations come from a single goroutine in main.runServe.
//
// Pointer is safe for concurrent use.
type Pointer struct {
	v atomic.Pointer[Config]
}

// NewPointer constructs a Pointer pre-loaded with c.
func NewPointer(c *Config) *Pointer {
	p := &Pointer{}
	p.v.Store(c)
	return p
}

// Load returns the current Config. The returned pointer should be treated as
// read-only; callers must not mutate it.
func (p *Pointer) Load() *Config { return p.v.Load() }

// Store atomically replaces the current Config.
func (p *Pointer) Store(c *Config) { p.v.Store(c) }

// ReloadCompatible reports whether `next` can replace `prev` without a full
// process restart. The fields that *cannot* change at runtime are:
//
//   - listen.address / listen.socket — would require re-binding sockets.
//   - ssh_ca.key_file / ssh_ca.host_ca_key_file — would invalidate every
//     in-flight cert tied to the previous CA.
//
// Returns nil if compatible; otherwise an error describing the first
// incompatibility found.
func ReloadCompatible(prev, next *Config) error {
	if prev.Listen != next.Listen {
		return errReloadField("listen")
	}
	// Enabled toggle gets checked before the path fields so the diagnostic
	// names the toggle (the meaningful intent) rather than a path that only
	// changed as a consequence.
	if prev.SSHCA.Enabled != next.SSHCA.Enabled {
		return errReloadField("ssh_ca.enabled")
	}
	if prev.SSHCA.KeyFile != next.SSHCA.KeyFile {
		return errReloadField("ssh_ca.key_file")
	}
	if prev.SSHCA.HostCAKeyFile != next.SSHCA.HostCAKeyFile {
		return errReloadField("ssh_ca.host_ca_key_file")
	}
	return nil
}

type reloadFieldErr struct{ Field string }

func (e *reloadFieldErr) Error() string {
	return "cannot reload " + e.Field + " at runtime — restart braingler to change it"
}

func errReloadField(f string) error { return &reloadFieldErr{Field: f} }
