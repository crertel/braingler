package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"time"

	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/events"
)

// apiActionResponse is what the wake/shutdown endpoints return on success.
// The action_id is a correlation handle: cheap enough to generate per call,
// useful for matching action attempts to later events in the audit log.
type apiActionResponse struct {
	ActionID string `json:"action_id"`
	Host     string `json:"host"`
	Action   string `json:"action"`
	Status   string `json:"status"` // "submitted" — finer state lives in the events log
}

func newActionID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) handleAPIWake(w http.ResponseWriter, r *http.Request) {
	h, ok := s.requireAPIHostPerm(w, r, config.ActionWake)
	if !ok {
		return
	}
	actor := principalFromContext(r.Context()).Name
	actionID := newActionID()
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	if err := s.wake(ctx, h); err != nil {
		s.logger.Warn("api wake failed", "host", h.Name, "err", err)
		s.recordEvent(events.Event{Host: h.Name, Kind: events.KindWakeFailed,
			Actor: actor, ActionID: actionID, Error: err.Error()})
		writeAPIError(w, http.StatusInternalServerError, "wake_failed", err.Error())
		return
	}
	s.logger.Info("api wake sent", "host", h.Name, "action_id", actionID, "actor", actor)
	s.recordEvent(events.Event{Host: h.Name, Kind: events.KindWakeSent,
		Actor: actor, ActionID: actionID})
	writeJSON(w, http.StatusAccepted, apiActionResponse{
		ActionID: actionID, Host: h.Name, Action: config.ActionWake, Status: "submitted",
	})
}

func (s *Server) handleAPIShutdown(w http.ResponseWriter, r *http.Request) {
	h, ok := s.requireAPIHostPerm(w, r, config.ActionShutdown)
	if !ok {
		return
	}
	actor := principalFromContext(r.Context()).Name
	actionID := newActionID()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()
	if err := s.shutdown(ctx, h, s.cfg.EffectiveSSH(h)); err != nil {
		s.logger.Warn("api shutdown failed", "host", h.Name, "err", err)
		s.recordEvent(events.Event{Host: h.Name, Kind: events.KindShutdownFail,
			Actor: actor, ActionID: actionID, Error: err.Error()})
		writeAPIError(w, http.StatusInternalServerError, "shutdown_failed", err.Error())
		return
	}
	s.logger.Info("api shutdown sent", "host", h.Name, "action_id", actionID, "actor", actor)
	s.recordEvent(events.Event{Host: h.Name, Kind: events.KindShutdownSent,
		Actor: actor, ActionID: actionID})
	writeJSON(w, http.StatusAccepted, apiActionResponse{
		ActionID: actionID, Host: h.Name, Action: config.ActionShutdown, Status: "submitted",
	})
}

// recordEvent is a tiny wrapper so handlers don't have to nil-check the log.
func (s *Server) recordEvent(e events.Event) {
	if s.events != nil {
		s.events.Append(e)
	}
}

// requireAPIHostPerm looks up the host by path param and verifies the caller
// has the requested action on it. It writes a 404 (host unknown or invisible)
// or 403 (host visible but action denied) on failure so agents can tell the
// two apart and surface the right error to the user.
func (s *Server) requireAPIHostPerm(w http.ResponseWriter, r *http.Request, action string) (*config.Host, bool) {
	h := s.cfg.HostByName(r.PathValue("name"))
	if h == nil {
		writeAPIError(w, http.StatusNotFound, "host_not_found", "no such host")
		return nil, false
	}
	if !s.canDo(r, h.Name, config.ActionStatus) {
		// Treat invisible hosts as nonexistent — don't leak their names.
		writeAPIError(w, http.StatusNotFound, "host_not_found", "no such host")
		return nil, false
	}
	if !s.canDo(r, h.Name, action) {
		writeAPIError(w, http.StatusForbidden, "action_forbidden",
			"not permitted to "+action+" "+h.Name)
		return nil, false
	}
	return h, true
}
