package server

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/crertel/braingler/internal/config"
)

// handleIndex renders the full dashboard.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	views := make([]hostView, 0, len(s.cfg.Hosts))
	for i := range s.cfg.Hosts {
		h := &s.cfg.Hosts[i]
		if !s.canDo(r, h.Name, config.ActionStatus) {
			continue
		}
		st, _ := s.registry.Get(h.Name)
		views = append(views, newHostView(h, st, s.cfg.PollIntervalSeconds,
			s.canDo(r, h.Name, config.ActionWake),
			s.canDo(r, h.Name, config.ActionShutdown)))
	}

	data := map[string]any{
		"Hosts":       views,
		"HostCount":   len(views),
		"PollSeconds": s.cfg.PollIntervalSeconds,
	}
	s.render(w, "index.html", data)
}

// handleHostCard returns a single host card fragment — what HTMX swaps in
// on every poll tick.
func (s *Server) handleHostCard(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	h := s.cfg.HostByName(name)
	if h == nil || !s.canDo(r, name, config.ActionStatus) {
		http.NotFound(w, r)
		return
	}
	st, _ := s.registry.Get(name)
	v := newHostView(h, st, s.cfg.PollIntervalSeconds,
		s.canDo(r, name, config.ActionWake),
		s.canDo(r, name, config.ActionShutdown))
	s.render(w, "host_card.html", v)
}

func (s *Server) handleWake(w http.ResponseWriter, r *http.Request) {
	h := s.cfg.HostByName(r.PathValue("name"))
	if h == nil || !s.canDo(r, h.Name, config.ActionWake) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.wake(ctx, h); err != nil {
		s.logger.Warn("wake failed", "host", h.Name, "err", err)
		http.Error(w, "wake failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.logger.Info("wake sent", "host", h.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleShutdown(w http.ResponseWriter, r *http.Request) {
	h := s.cfg.HostByName(r.PathValue("name"))
	if h == nil || !s.canDo(r, h.Name, config.ActionShutdown) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.shutdown(ctx, h, s.cfg.EffectiveSSH(h)); err != nil {
		s.logger.Warn("shutdown failed", "host", h.Name, "err", err)
		http.Error(w, "shutdown failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	s.logger.Info("shutdown sent", "host", h.Name)
	w.WriteHeader(http.StatusNoContent)
}

// render buffers template output before writing to w so a template error
// produces a clean 500 instead of half a page.
func (s *Server) render(w http.ResponseWriter, name string, data any) {
	var buf bytes.Buffer
	if err := s.tmpl.ExecuteTemplate(&buf, name, data); err != nil {
		s.logger.Error("template", "name", name, "err", err)
		if errors.Is(err, context.Canceled) {
			return
		}
		http.Error(w, fmt.Sprintf("template %s: %v", name, err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}
