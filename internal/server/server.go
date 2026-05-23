// Package server is the HTTP layer: routing, templates, action handlers.
//
// Auth (step 8) is not yet wired in; for now every request is treated as
// having full access. The Server.canDo hook is the seam where group/action
// checks will plug in later.
package server

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/crertel/braingler/internal/auth"
	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/events"
	"github.com/crertel/braingler/internal/hosts"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

//go:embed openapi.json
var openapiSpec []byte

// Server bundles dependencies the handlers need. Construct via New.
type Server struct {
	cfg      *config.Config
	registry *hosts.Registry
	logger   *slog.Logger
	tmpl     *template.Template
	wake     WakeFunc
	shutdown ShutdownFunc
	authn    *auth.Authenticator // nil if auth is disabled in config
	events   *events.Log         // nil disables the audit log
}

// WakeFunc and ShutdownFunc are injected so the server doesn't import wol/sshx
// directly — keeps the dependency graph one-way and makes the handlers
// trivial to test with stubs.
type WakeFunc func(ctx context.Context, h *config.Host) error
type ShutdownFunc func(ctx context.Context, h *config.Host, cfg config.SSHConfig) error

func New(cfg *config.Config, reg *hosts.Registry, logger *slog.Logger,
	authn *auth.Authenticator, evts *events.Log,
	wake WakeFunc, shutdown ShutdownFunc) (*Server, error) {
	if logger == nil {
		logger = slog.Default()
	}
	tmpl, err := template.New("").Funcs(templateFuncs).ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, fmt.Errorf("parse templates: %w", err)
	}
	return &Server{
		cfg: cfg, registry: reg, logger: logger,
		tmpl: tmpl, wake: wake, shutdown: shutdown, authn: authn, events: evts,
	}, nil
}

// Handler builds the http.Handler tree. Separating it from ListenAndServe
// makes the server testable via httptest.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		// Static is bundled at build time — this can only fail on a broken
		// build, so panic is correct.
		panic(fmt.Errorf("static sub-fs: %w", err))
	}
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(staticSub)))

	// Public endpoints (no auth required).
	mux.HandleFunc("GET /login", s.handleLoginGet)
	mux.HandleFunc("POST /login", s.handleLoginPost)
	mux.HandleFunc("POST /logout", s.handleLogout)

	// Browser routes — cookie auth only.
	mux.Handle("GET /{$}", s.requireAuth(http.HandlerFunc(s.handleIndex)))
	mux.Handle("GET /events", s.requireAuth(http.HandlerFunc(s.handleEvents)))
	mux.Handle("GET /hosts/{name}", s.requireAuth(http.HandlerFunc(s.handleHostCard)))
	mux.Handle("POST /hosts/{name}/wake", s.requireAuth(http.HandlerFunc(s.handleWake)))
	mux.Handle("POST /hosts/{name}/shutdown", s.requireAuth(http.HandlerFunc(s.handleShutdown)))

	// JSON API — bearer or cookie auth.
	// The spec itself is unauthenticated so agents can discover the API
	// before they're trusted enough to call it.
	mux.HandleFunc("GET /api/v1/openapi.json", s.handleOpenAPISpec)

	mux.Handle("GET /api/v1/whoami", s.requireAPIAuth(http.HandlerFunc(s.handleAPIWhoami)))
	mux.Handle("GET /api/v1/hosts", s.requireAPIAuth(http.HandlerFunc(s.handleAPIHostList)))
	mux.Handle("GET /api/v1/hosts/{name}", s.requireAPIAuth(http.HandlerFunc(s.handleAPIHost)))
	mux.Handle("POST /api/v1/hosts/{name}/wake", s.requireAPIAuth(http.HandlerFunc(s.handleAPIWake)))
	mux.Handle("POST /api/v1/hosts/{name}/shutdown", s.requireAPIAuth(http.HandlerFunc(s.handleAPIShutdown)))
	mux.Handle("GET /api/v1/events", s.requireAPIAuth(http.HandlerFunc(s.handleAPIEvents)))
	mux.Handle("GET /api/v1/events/stream", s.requireAPIAuth(http.HandlerFunc(s.handleAPIEventsStream)))

	return s.logging(mux)
}

// ListenAndServe binds and serves until ctx is canceled. It honors either a
// TCP address or a Unix socket path from config.Listen.
func (s *Server) ListenAndServe(ctx context.Context) error {
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	ln, cleanup, err := s.listener()
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	s.logger.Info("http listening", "addr", ln.Addr())
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (s *Server) listener() (net.Listener, func(), error) {
	switch {
	case s.cfg.Listen.Socket != "":
		path := s.cfg.Listen.Socket
		// A stale socket from a previous run will refuse to bind. Removing
		// it is safe only if it's actually a socket — guard against the
		// caller accidentally pointing at a real file.
		if info, err := os.Stat(path); err == nil {
			if info.Mode().Type()&os.ModeSocket == 0 {
				return nil, nil, fmt.Errorf("listen.socket %q exists and is not a socket", path)
			}
			if err := os.Remove(path); err != nil {
				return nil, nil, fmt.Errorf("remove stale socket %s: %w", path, err)
			}
		}
		if dir := filepath.Dir(path); dir != "." && dir != "/" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				return nil, nil, fmt.Errorf("mkdir %s: %w", dir, err)
			}
		}
		ln, err := net.Listen("unix", path)
		if err != nil {
			return nil, nil, err
		}
		if err := os.Chmod(path, 0o660); err != nil {
			ln.Close()
			return nil, nil, fmt.Errorf("chmod %s: %w", path, err)
		}
		return ln, func() { os.Remove(path) }, nil
	default:
		ln, err := net.Listen("tcp", s.cfg.Listen.Address)
		return ln, nil, err
	}
}

// handleOpenAPISpec serves the bundled spec. Cached aggressively since it's
// baked into the binary.
func (s *Server) handleOpenAPISpec(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = w.Write(openapiSpec)
}

// canDo checks whether the request's authenticated principal is permitted
// to take action on hostName. When auth is disabled, all requests are allowed.
func (s *Server) canDo(r *http.Request, hostName, action string) bool {
	if !s.cfg.Auth.Enabled {
		return true
	}
	p := principalFromContext(r.Context())
	if p.Name == "" {
		return false
	}
	return s.cfg.PrincipalCan(p, hostName, action)
}

// logging emits one structured line per request with method, path, status,
// and duration. Cheap accountability — useful when ssh actions misbehave.
func (s *Server) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		s.logger.Info("http",
			"method", r.Method, "path", r.URL.Path,
			"status", sw.status, "dur_ms", time.Since(start).Milliseconds())
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(s int) {
	w.status = s
	w.ResponseWriter.WriteHeader(s)
}

// Unwrap exposes the underlying ResponseWriter so http.NewResponseController
// can reach Flush/Hijack on the original — the SSE handler relies on this.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
