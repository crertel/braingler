// Package hosts holds the in-memory status registry: the latest known state
// of every monitored host. The HTTP layer reads from here; the monitor writes.
package hosts

import (
	"sync"
	"time"
)

// Reachability is a tri-state. "Unknown" lets the UI distinguish a host that
// has never been polled from one that has been confirmed down.
type Reachability int

const (
	Unknown Reachability = iota
	Down
	Up
)

func (r Reachability) String() string {
	switch r {
	case Up:
		return "up"
	case Down:
		return "down"
	default:
		return "unknown"
	}
}

// Status is one host's current snapshot. The SSH-derived fields are only
// populated when the host is reachable and the corresponding check is enabled.
type Status struct {
	Name        string
	Reachable   Reachability
	LastChecked time.Time
	LastChange  time.Time
	LastErr     string

	Uptime time.Duration
	Load   LoadInfo
	Memory MemInfo
	Disks  []DiskInfo
}

// LoadInfo holds the 1/5/15-minute load averages from /proc/loadavg.
type LoadInfo struct {
	One     float64
	Five    float64
	Fifteen float64
}

// MemInfo holds two figures from /proc/meminfo, in kilobytes. AvailableKB is
// "MemAvailable" — the kernel's estimate of memory usable for new allocations
// without swapping, which tracks "free + reclaimable" better than MemFree.
type MemInfo struct {
	TotalKB     int
	AvailableKB int
}

// DiskInfo is one entry from df, filtered to real filesystems (no tmpfs etc).
type DiskInfo struct {
	Mount   string
	FSType  string
	UsedPct int
}

// Registry is a goroutine-safe map of host name -> Status, preserving the
// registration order so the UI can render in a stable sequence. Subscribers
// receive a copy of each Status on every Update.
type Registry struct {
	mu       sync.RWMutex
	statuses map[string]Status
	order    []string
	subs     map[chan Status]struct{}
}

func New() *Registry {
	return &Registry{
		statuses: map[string]Status{},
		subs:     map[chan Status]struct{}{},
	}
}

// Subscribe returns a channel that receives every Status update and a function
// to unregister. The channel is buffered; if a subscriber falls behind, sends
// are dropped rather than blocking the writer. Call the returned unsubscribe
// exactly once.
func (r *Registry) Subscribe() (<-chan Status, func()) {
	ch := make(chan Status, 16)
	r.mu.Lock()
	r.subs[ch] = struct{}{}
	r.mu.Unlock()
	var once sync.Once
	unsub := func() {
		once.Do(func() {
			r.mu.Lock()
			delete(r.subs, ch)
			r.mu.Unlock()
			close(ch)
		})
	}
	return ch, unsub
}

// publish must be called with r.mu held (for the snapshot read) or after
// releasing it; we take the simpler shape and call it after the mutate while
// still holding the lock, so subscribers see updates in serialized order.
func (r *Registry) publish(s Status) {
	for ch := range r.subs {
		select {
		case ch <- s:
		default:
			// Drop on full buffer — subscriber is slow and will catch up
			// on the next update.
		}
	}
}

// Register adds a host with default Status if it doesn't already exist.
func (r *Registry) Register(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.statuses[name]; exists {
		return
	}
	r.statuses[name] = Status{Name: name, Reachable: Unknown}
	r.order = append(r.order, name)
}

// Get returns a copy of the named host's status.
func (r *Registry) Get(name string) (Status, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.statuses[name]
	return s, ok
}

// Snapshot returns all statuses in registration order.
func (r *Registry) Snapshot() []Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Status, 0, len(r.order))
	for _, n := range r.order {
		out = append(out, r.statuses[n])
	}
	return out
}

// Update applies mutate to a copy of the named status, stores the result, and
// returns the previous reachability so callers can detect transitions. If the
// host isn't registered, Update is a no-op and reports (Unknown, false).
func (r *Registry) Update(name string, mutate func(*Status)) (prev Reachability, ok bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	s, exists := r.statuses[name]
	if !exists {
		return Unknown, false
	}
	prev = s.Reachable
	mutate(&s)
	if s.Reachable != prev {
		s.LastChange = s.LastChecked
	}
	r.statuses[name] = s
	r.publish(s)
	return prev, true
}
