// Package events is the in-memory event log: a bounded ring of interesting
// things that happened (host went up/down, wake/shutdown was attempted).
// Stored in memory only — sqlite is a separate concern when/if needed.
package events

import (
	"sync"
	"time"
)

// Kind enumerates the event types so callers can filter without parsing
// strings. Adding new kinds is cheap; the API surface treats them as opaque.
const (
	KindStateChange   = "state_change"
	KindWakeSent      = "wake_sent"
	KindWakeFailed    = "wake_failed"
	KindShutdownSent  = "shutdown_sent"
	KindShutdownFail  = "shutdown_failed"
)

// Event is one entry in the log. Fields beyond the common four are populated
// only for the kinds that need them.
type Event struct {
	ID   uint64    `json:"id"`
	TS   time.Time `json:"ts"`
	Host string    `json:"host"`
	Kind string    `json:"kind"`

	// State change.
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`

	// Action attempts.
	Actor    string `json:"actor,omitempty"`
	ActionID string `json:"action_id,omitempty"`

	// Failures.
	Error string `json:"error,omitempty"`
}

// Log is a goroutine-safe bounded event buffer with pub/sub for live streams.
type Log struct {
	mu     sync.RWMutex
	items  []Event
	cap    int
	nextID uint64
	subs   map[chan Event]struct{}
}

// New builds an empty log with the given capacity. Capacity <1 falls back to
// a small default — a zero-cap log silently drops everything, which would be
// confusing for callers.
func New(capacity int) *Log {
	if capacity < 1 {
		capacity = 1024
	}
	return &Log{
		cap:   capacity,
		items: make([]Event, 0, capacity),
		subs:  map[chan Event]struct{}{},
	}
}

// Append records e, assigning it a monotonic ID and a UTC timestamp. The
// caller-supplied ID/TS on e are overwritten. Subscribers see the event
// after it's been stored.
func (l *Log) Append(e Event) Event {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nextID++
	e.ID = l.nextID
	e.TS = time.Now().UTC()
	if len(l.items) >= l.cap {
		// Drop the oldest entry. O(n) but n is bounded; fine.
		l.items = l.items[1:]
	}
	l.items = append(l.items, e)
	for ch := range l.subs {
		select {
		case ch <- e:
		default:
			// Slow subscriber — drop the event for them.
		}
	}
	return e
}

// Since returns events with ID > sinceID, oldest first, optionally filtered
// and capped. limit<=0 means "no cap". filter==nil means "no filter".
func (l *Log) Since(sinceID uint64, limit int, filter func(Event) bool) []Event {
	l.mu.RLock()
	defer l.mu.RUnlock()
	out := make([]Event, 0)
	for _, e := range l.items {
		if e.ID <= sinceID {
			continue
		}
		if filter != nil && !filter(e) {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

// Subscribe returns a channel that receives every new event plus an
// unsubscribe function. The channel is buffered; sends drop on overflow
// rather than blocking the producer.
func (l *Log) Subscribe() (<-chan Event, func()) {
	ch := make(chan Event, 64)
	l.mu.Lock()
	l.subs[ch] = struct{}{}
	l.mu.Unlock()
	var once sync.Once
	unsub := func() {
		once.Do(func() {
			l.mu.Lock()
			delete(l.subs, ch)
			l.mu.Unlock()
			close(ch)
		})
	}
	return ch, unsub
}

// LatestID returns the most recent event ID (or 0 if empty). Useful for
// clients that want to start a stream from "now, not history."
func (l *Log) LatestID() uint64 {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.nextID
}
