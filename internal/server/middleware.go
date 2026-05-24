package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/crertel/braingler/internal/auth"
	"github.com/crertel/braingler/internal/config"
)

// ctxKey is unexported so external packages can't accidentally clobber our
// principal-in-context value.
type ctxKey struct{}

var principalCtxKey = ctxKey{}

// principalFromContext returns the authenticated principal, or zero value.
func principalFromContext(ctx context.Context) config.Principal {
	p, _ := ctx.Value(principalCtxKey).(config.Principal)
	return p
}

// resolveCookie tries to authenticate the request via the session cookie.
// Returns the principal on success and ok=false on absence/invalidity.
func (s *Server) resolveCookie(r *http.Request) (config.Principal, bool) {
	if s.authn == nil {
		return config.Principal{}, false
	}
	username := s.authn.UserFromRequest(r)
	if username == "" {
		return config.Principal{}, false
	}
	u := s.cfg().LookupUser(username)
	if u == nil {
		// Cookie valid for a username that's no longer in config — treat
		// as unauthenticated and let the user log in again.
		return config.Principal{}, false
	}
	return config.Principal{
		Name: u.Username, Kind: config.PrincipalUser, Groups: u.Groups,
	}, true
}

// resolveBearer tries to authenticate the request via Authorization: Bearer.
// Returns the principal on success and ok=false on absence/invalidity.
func (s *Server) resolveBearer(r *http.Request) (config.Principal, bool) {
	tok := auth.PresentedBearer(r.Header.Get("Authorization"))
	if tok == "" {
		return config.Principal{}, false
	}
	rec, err := auth.VerifyToken(s.cfg(), tok)
	if err != nil {
		return config.Principal{}, false
	}
	return config.Principal{
		Name: rec.Name, Kind: config.PrincipalAgent, Groups: rec.Groups,
	}, true
}

// requireAuth gates the browser-facing HTML routes. Only cookie auth is
// accepted here; unauthenticated requests get redirected to /login.
func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg().Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		p, ok := s.resolveCookie(r)
		if !ok {
			s.redirectToLogin(w, r)
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalCtxKey, p)))
	})
}

// requireAPIAuth gates /api routes. It accepts EITHER a bearer token (the
// expected agent path) OR a session cookie (handy when an authenticated
// human pokes the API from a browser). Failures return JSON 401 — no
// HTML redirects on the API surface.
func (s *Server) requireAPIAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.cfg().Auth.Enabled {
			next.ServeHTTP(w, r)
			return
		}
		if p, ok := s.resolveBearer(r); ok {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalCtxKey, p)))
			return
		}
		if p, ok := s.resolveCookie(r); ok {
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), principalCtxKey, p)))
			return
		}
		writeAPIError(w, http.StatusUnauthorized, "unauthorized",
			"provide an Authorization: Bearer <token> header or a session cookie")
	})
}

// redirectToLogin sends an unauthenticated client to /login, preserving the
// originally-requested path. HTMX-initiated requests get an HX-Redirect
// header so the client navigates instead of trying to swap a login page.
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
