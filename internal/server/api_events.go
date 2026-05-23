package server

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/events"
)

const (
	defaultEventsLimit = 200
	maxEventsLimit     = 1000
)

// apiEventsPage is the response for GET /api/v1/events.
type apiEventsPage struct {
	Events   []events.Event `json:"events"`
	LatestID uint64         `json:"latest_id"` // newest ID present in the log overall
	NextID   uint64         `json:"next_id"`   // pass back as ?since=NEXT to keep paging
}

// handleAPIEvents serves the paged event log. Events are filtered to hosts
// the principal can see — an agent never learns about a host they don't have
// visibility on.
func (s *Server) handleAPIEvents(w http.ResponseWriter, r *http.Request) {
	if s.events == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "no_event_log",
			"event log is not configured on this server")
		return
	}

	q := r.URL.Query()
	sinceID, _ := strconv.ParseUint(q.Get("since"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 {
		limit = defaultEventsLimit
	}
	if limit > maxEventsLimit {
		limit = maxEventsLimit
	}
	hostFilter := q.Get("host")

	canSee := s.hostFilter(r, hostFilter)
	evts := s.events.Since(sinceID, limit, canSee)

	page := apiEventsPage{
		Events:   evts,
		LatestID: s.events.LatestID(),
	}
	if len(evts) > 0 {
		page.NextID = evts[len(evts)-1].ID
	} else {
		page.NextID = sinceID
	}
	writeJSON(w, http.StatusOK, page)
}

// handleAPIEventsStream pushes new events as SSE, in JSON. Designed for an
// agent that wants to "tail -f" the audit log: it gets a synthetic ":start"
// comment, then one event per state change or action.
func (s *Server) handleAPIEventsStream(w http.ResponseWriter, r *http.Request) {
	if s.events == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "no_event_log",
			"event log is not configured on this server")
		return
	}

	rc := http.NewResponseController(w)
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		return
	}

	canSee := s.hostFilter(r, r.URL.Query().Get("host"))

	// Optionally replay since=ID before streaming live, so a reconnecting
	// agent doesn't have to fetch /events separately to catch up.
	if sinceStr := r.URL.Query().Get("since"); sinceStr != "" {
		sinceID, _ := strconv.ParseUint(sinceStr, 10, 64)
		for _, e := range s.events.Since(sinceID, maxEventsLimit, canSee) {
			if err := writeEvent(w, e); err != nil {
				return
			}
		}
		_ = rc.Flush()
	}

	ch, unsub := s.events.Subscribe()
	defer unsub()

	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprint(w, ": heartbeat\n\n"); err != nil {
				return
			}
			_ = rc.Flush()
		case e, ok := <-ch:
			if !ok {
				return
			}
			if !canSee(e) {
				continue
			}
			if err := writeEvent(w, e); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}

// hostFilter returns a predicate that says "this event is visible to the
// caller and matches an optional ?host=foo query." Used by both the paged
// and streaming endpoints so they apply identical visibility rules.
func (s *Server) hostFilter(r *http.Request, only string) func(events.Event) bool {
	return func(e events.Event) bool {
		if only != "" && e.Host != only {
			return false
		}
		return s.canDo(r, e.Host, config.ActionStatus)
	}
}

func writeEvent(w http.ResponseWriter, e events.Event) error {
	// One JSON object per event line. No multi-line nonsense to escape.
	b, err := encodeCompactJSON(e)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Kind, b)
	return err
}
