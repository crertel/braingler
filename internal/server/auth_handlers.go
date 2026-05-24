package server

import (
	"net/http"

	"github.com/crertel/braingler/internal/auth"
)

func (s *Server) handleLoginGet(w http.ResponseWriter, r *http.Request) {
	// Already signed in? Bounce back to the dashboard.
	if s.cfg().Auth.Enabled && s.authn != nil && s.authn.UserFromRequest(r) != "" {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.render(w, "login.html", map[string]any{
		"Next": r.URL.Query().Get("next"),
	})
}

func (s *Server) handleLoginPost(w http.ResponseWriter, r *http.Request) {
	if !s.cfg().Auth.Enabled || s.authn == nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")
	next := r.PostForm.Get("next")
	if next == "" || next[0] != '/' {
		next = "/"
	}

	if err := s.authn.VerifyCredentials(username, password); err != nil {
		if auth.IsInvalidCredentials(err) {
			s.logger.Info("login failed", "username", username)
			w.WriteHeader(http.StatusUnauthorized)
			s.render(w, "login.html", map[string]any{
				"Error": "Invalid username or password.",
				"Next":  next,
			})
			return
		}
		s.logger.Error("login error", "err", err)
		http.Error(w, "login error", http.StatusInternalServerError)
		return
	}

	http.SetCookie(w, s.authn.IssueCookie(username))
	s.logger.Info("login ok", "username", username)
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if s.authn != nil {
		http.SetCookie(w, s.authn.ClearCookie())
	}
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", "/login")
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
