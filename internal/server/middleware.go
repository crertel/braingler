package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/crertel/braingler/internal/auth"
)

// ctxKey is unexported so external packages can't accidentally clobber our
// user-in-context value.
type ctxKey struct{}

var userCtxKey = ctxKey{}

// userFromContext returns the authenticated username in r, or "".
func userFromContext(ctx context.Context) string {
	u, _ := ctx.Value(userCtxKey).(string)
	return u
}

// requireAuth wraps next to enforce that the caller has a valid session.
// If auth is disabled in config, this is a passthrough.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg.Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		if s.authn == nil {
			http.Error(w, "auth not configured", http.StatusInternalServerError)
			return
		}
		user := s.authn.UserFromRequest(r)
		if user == "" {
			s.redirectToLogin(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), userCtxKey, user)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// redirectToLogin sends an unauthenticated client to /login, preserving the
// originally-requested path so we can bounce them back after sign-in.
// HTMX-initiated requests get an HX-Redirect header instead of a 30x — HTMX
// follows it client-side without trying to swap a login page into a fragment.
func (s *Server) redirectToLogin(w http.ResponseWriter, r *http.Request) {
	target := "/login"
	if r.URL.Path != "/" && r.URL.Path != "/login" {
		target += "?next=" + url.QueryEscape(r.URL.Path)
	}
	if isHTMX(r) {
		w.Header().Set("HX-Redirect", target)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, target, http.StatusSeeOther)
}

func isHTMX(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("HX-Request"), "true")
}

// Compile-time check that Authenticator is the type we expect.
var _ = (*auth.Authenticator)(nil)