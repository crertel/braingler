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
