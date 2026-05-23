package events

import (
	"testing"
	"time"
)

func TestAppendAssignsMonotonicIDs(t *testing.T) {
	l := New(10)
	a := l.Append(Event{Host: "h", Kind: KindStateChange, From: "down", To: "up"})
	b := l.Append(Event{Host: "h", Kind: KindStateChange, From: "up", To: "down"})
	if a.ID != 1 || b.ID != 2 {
		t.Errorf("ids = %d,%d, want 1,2", a.ID, b.ID)
	}
	if a.TS.IsZero() || b.TS.IsZero() {
		t.Error("timestamps not set")
	}
	if !b.TS.After(a.TS) && !b.TS.Equal(a.TS) {
		t.Errorf("b ts %v should be >= a ts %v", b.TS, a.TS)
	}
}

func TestSinceFilterAndLimit(t *testing.T) {
	l := New(10)
	for _, h := range []string{"a", "b", "a", "c", "b"} {
		l.Append(Event{Host: h, Kind: KindStateChange})
	}
	// All, no filter
	all := l.Since(0, 0, nil)
	if len(all) != 5 {
		t.Fatalf("got %d, want 5", len(all))
	}
	// since=2 → events 3..5
	tail := l.Since(2, 0, nil)
	if len(tail) != 3 || tail[0].ID != 3 {
		t.Errorf("since=2 returned %d events starting at %d", len(tail), tail[0].ID)
	}
	// limit=2
	cap2 := l.Since(0, 2, nil)
	if len(cap2) != 2 {
		t.Errorf("limit=2 returned %d", len(cap2))
	}
	// filter host=="a"
	onlyA := l.Since(0, 0, func(e Event) bool { return e.Host == "a" })
	if len(onlyA) != 2 {
		t.Errorf("filter host=a returned %d", len(onlyA))
	}
}

func TestRingDropsOldestAtCapacity(t *testing.T) {
	l := New(3)
	for range 5 {
		l.Append(Event{Host: "h"})
	}
	all := l.Since(0, 0, nil)
	if len(all) != 3 {
		t.Fatalf("ring size = %d, want 3", len(all))
	}
	// Should contain IDs 3, 4, 5 — the most recent 3.
	if all[0].ID != 3 || all[2].ID != 5 {
		t.Errorf("ring contents: ids %d..%d, want 3..5", all[0].ID, all[2].ID)
	}
	// Even after old IDs roll off, LatestID still climbs monotonically.
	if l.LatestID() != 5 {
		t.Errorf("LatestID = %d, want 5", l.LatestID())
	}
}

func TestSubscribeReceives(t *testing.T) {
	l := New(10)
	ch, unsub := l.Subscribe()
	defer unsub()

	l.Append(Event{Host: "h", Kind: KindWakeSent})
	select {
	case e := <-ch:
		if e.Host != "h" || e.Kind != KindWakeSent {
			t.Errorf("got %+v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("subscribe did not deliver event")
	}
}

func TestSubscribeDropsOnOverflow(t *testing.T) {
	l := New(1000)
	ch, unsub := l.Subscribe()
	defer unsub()
	// Buffer is 64; push 200 without reading. Must not block.
	done := make(chan struct{})
	go func() {
		for range 200 {
			l.Append(Event{Host: "h"})
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher blocked")
	}
	// Drain — should at least have something buffered.
	got := 0
	for {
		select {
		case <-ch:
			got++
		default:
			if got == 0 {
				t.Error("expected some events to make it through")
			}
			return
		}
	}
}

func TestUnsubscribeClosesChannel(t *testing.T) {
	l := New(10)
	ch, unsub := l.Subscribe()
	unsub()
	if _, ok := <-ch; ok {
		t.Error("channel should be closed after unsubscribe")
	}
	// Subsequent appends must not panic.
	l.Append(Event{Host: "h"})
}
