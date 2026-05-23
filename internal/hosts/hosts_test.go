package hosts

import (
	"testing"
	"time"
)

func TestRegisterAndSnapshotPreserveOrder(t *testing.T) {
	r := New()
	r.Register("c")
	r.Register("a")
	r.Register("b")
	r.Register("a") // duplicate — no-op
	snap := r.Snapshot()
	got := []string{snap[0].Name, snap[1].Name, snap[2].Name}
	want := []string{"c", "a", "b"}
	if len(snap) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("Snapshot order: got %v, want %v", got, want)
	}
}

func TestUpdateDetectsTransition(t *testing.T) {
	r := New()
	r.Register("h")

	prev, ok := r.Update("h", func(s *Status) {
		s.Reachable = Up
		s.LastChecked = time.Unix(100, 0)
	})
	if !ok || prev != Unknown {
		t.Fatalf("first update: prev=%v ok=%v, want Unknown,true", prev, ok)
	}
	s, _ := r.Get("h")
	if s.LastChange != time.Unix(100, 0) {
		t.Errorf("LastChange not set on transition: %v", s.LastChange)
	}

	prev, _ = r.Update("h", func(s *Status) {
		s.Reachable = Up
		s.LastChecked = time.Unix(200, 0)
	})
	if prev != Up {
		t.Errorf("second update: prev=%v, want Up", prev)
	}
	s, _ = r.Get("h")
	if s.LastChange != time.Unix(100, 0) {
		t.Errorf("LastChange must not move when state unchanged: %v", s.LastChange)
	}

	r.Update("h", func(s *Status) {
		s.Reachable = Down
		s.LastChecked = time.Unix(300, 0)
	})
	s, _ = r.Get("h")
	if s.LastChange != time.Unix(300, 0) {
		t.Errorf("LastChange must update on transition Up->Down: %v", s.LastChange)
	}
}

func TestUpdateUnknownHostNoop(t *testing.T) {
	r := New()
	prev, ok := r.Update("ghost", func(s *Status) { s.Reachable = Up })
	if ok || prev != Unknown {
		t.Errorf("ghost update: prev=%v ok=%v, want Unknown,false", prev, ok)
	}
}

func TestSubscribeReceivesUpdates(t *testing.T) {
	r := New()
	r.Register("h")
	ch, unsub := r.Subscribe()
	defer unsub()

	r.Update("h", func(s *Status) { s.Reachable = Up })

	select {
	case st := <-ch:
		if st.Reachable != Up || st.Name != "h" {
			t.Errorf("got %+v, want h/Up", st)
		}
	case <-time.After(time.Second):
		t.Fatal("subscribe did not receive update")
	}
}

func TestSubscribeDropsWhenFull(t *testing.T) {
	r := New()
	r.Register("h")
	ch, unsub := r.Subscribe()
	defer unsub()

	// Buffer is 16; push 50 updates without consuming. Should not block.
	done := make(chan struct{})
	go func() {
		for range 50 {
			r.Update("h", func(s *Status) { s.Reachable = Up })
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("publisher blocked — full channel should drop, not block")
	}
	// Drain to confirm we got *something* (the buffered prefix).
	got := 0
	for {
		select {
		case <-ch:
			got++
		default:
			if got == 0 {
				t.Error("expected at least one buffered event")
			}
			return
		}
	}
}

func TestUnsubscribeStopsDelivery(t *testing.T) {
	r := New()
	r.Register("h")
	ch, unsub := r.Subscribe()

	r.Update("h", func(s *Status) { s.Reachable = Up })
	<-ch // drain
	unsub()

	// Channel should be closed; reading returns the zero value with !ok.
	if _, ok := <-ch; ok {
		t.Error("channel should be closed after unsubscribe")
	}

	// Further updates must not panic or send to a closed channel.
	r.Update("h", func(s *Status) { s.Reachable = Down })
}
