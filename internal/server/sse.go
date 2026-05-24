package server

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/hosts"
)

// handleEvents is the SSE endpoint that pushes one HTML host-card fragment
// per state change. The HTMX SSE extension consumes these and swaps the
// matching card by event name (`host-<name>`).
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	rc := http.NewResponseController(w)

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	// Reverse proxies (nginx in particular) buffer responses by default,
	// which defeats SSE. This opt-out is widely respected.
	h.Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	if err := rc.Flush(); err != nil {
		s.logger.Warn("sse flush headers", "err", err)
		return
	}

	ch, unsub := s.registry.Subscribe()
	defer unsub()

	// Initial snapshot of every visible host so a fresh connection renders
	// correctly without waiting for the next state change.
	for i := range s.cfg().Hosts {
		host := &s.cfg().Hosts[i]
		if !s.canDo(r, host.Name, config.ActionStatus) {
			continue
		}
		st, _ := s.registry.Get(host.Name)
		s.writeHostEvent(w, rc, host, st, r)
	}

	// Keep-alive comments every 15s keep proxies (and some browsers) from
	// giving up on an otherwise idle connection.
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
		case st, ok := <-ch:
			if !ok {
				return
			}
			host := s.cfg().HostByName(st.Name)
			if host == nil {
				continue
			}
			if !s.canDo(r, host.Name, config.ActionStatus) {
				continue
			}
			s.writeHostEvent(w, rc, host, st, r)
		}
	}
}

// writeHostEvent renders one host-card fragment and frames it as an SSE event
// named "host-<name>". The HTML body is rewritten so every embedded newline
// is prefixed with "data: ", which is what the SSE spec requires for
// multi-line payloads.
func (s *Server) writeHostEvent(w http.ResponseWriter, rc *http.ResponseController,
	h *config.Host, st hosts.Status, r *http.Request) {
	var buf bytes.Buffer
	v := newHostView(h, st, s.cfg().PollIntervalSeconds,
		s.canDo(r, h.Name, config.ActionWake),
		s.canDo(r, h.Name, config.ActionShutdown))
	if err := s.tmpl.ExecuteTemplate(&buf, "host_card.html", v); err != nil {
		s.logger.Error("sse render", "host", h.Name, "err", err)
		return
	}
	payload := strings.ReplaceAll(strings.TrimRight(buf.String(), "\n"), "\n", "\ndata: ")
	if _, err := fmt.Fprintf(w, "event: host-%s\ndata: %s\n\n", h.Name, payload); err != nil {
		return
	}
	_ = rc.Flush()
}
