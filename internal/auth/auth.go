// Package auth implements braingler's cookie-based session layer.
//
// Sessions are stateless: the cookie carries `username:expires_unix` plus an
// HMAC-SHA256 signature. There is no server-side session table to flush, so
// revocation works by rotating the secret key.
package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/crertel/braingler/internal/config"
	"golang.org/x/crypto/bcrypt"
)

const (
	// CookieName is the cookie set on successful login.
	CookieName = "braingler_session"
	// DefaultTTL is how long a session cookie remains valid.
	DefaultTTL = 30 * 24 * time.Hour
	// MinKeyBytes is the lower bound on the HMAC secret size.
	MinKeyBytes = 32
)

// Authenticator owns the signing key and exposes the cookie-and-perm helpers
// the HTTP layer needs. It is safe for concurrent use.
type Authenticator struct {
	cfgPtr *config.Pointer
	key    []byte
	ttl    time.Duration
}

// New constructs an Authenticator, loading or generating the HMAC secret at
// keyPath. The file is created with mode 0600 if it doesn't exist.
func New(cfgPtr *config.Pointer, keyPath string) (*Authenticator, error) {
	key, err := loadOrCreateKey(keyPath)
	if err != nil {
		return nil, err
	}
	return &Authenticator{cfgPtr: cfgPtr, key: key, ttl: DefaultTTL}, nil
}

// cfg loads the current config snapshot. Read-only.
func (a *Authenticator) cfg() *config.Config { return a.cfgPtr.Load() }

// VerifyCredentials checks (username, password) against the config. It
// returns the matched username and groups on success, or an error on
// failure. The error is deliberately vague — we don't want to leak whether
// the user existed.
func (a *Authenticator) VerifyCredentials(username, password string) error {
	for _, u := range a.cfg().Auth.Users {
		if u.Username != username {
			continue
		}
		if err := bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)); err != nil {
			return errInvalidCredentials
		}
		return nil
	}
	// Run a dummy bcrypt to keep the timing similar to a real check, so
	// observers can't tell "user not found" from "wrong password".
	_ = bcrypt.CompareHashAndPassword(
		[]byte("$2a$10$........................................................"),
		[]byte(password))
	return errInvalidCredentials
}

var errInvalidCredentials = errors.New("invalid username or password")

// IsInvalidCredentials reports whether err came from a failed login check.
func IsInvalidCredentials(err error) bool { return errors.Is(err, errInvalidCredentials) }

// IssueCookie produces a signed session cookie for username with the
// configured TTL.
func (a *Authenticator) IssueCookie(username string) *http.Cookie {
	exp := time.Now().Add(a.ttl)
	value := a.signValue(username, exp.Unix())
	return &http.Cookie{
		Name:     CookieName,
		Value:    value,
		Path:     "/",
		Expires:  exp,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		// We don't set Secure because this is typically reached over a
		// reverse-proxy or plain HTTP on the LAN. The proxy can rewrite if
		// it's terminating TLS.
	}
}

// ClearCookie returns a cookie that expires the existing session.
func (a *Authenticator) ClearCookie() *http.Cookie {
	return &http.Cookie{
		Name:     CookieName,
		Value:    "",
		Path:     "/",
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
}

// UserFromRequest returns the authenticated username, or "" if the request
// has no valid session cookie. Expired or tampered cookies return "".
func (a *Authenticator) UserFromRequest(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil || c.Value == "" {
		return ""
	}
	return a.verifyValue(c.Value)
}

// signValue builds the cookie payload: base64(username|expires) + "." + base64(hmac).
func (a *Authenticator) signValue(username string, expiresUnix int64) string {
	body := fmt.Sprintf("%s|%d", username, expiresUnix)
	mac := hmac.New(sha256.New, a.key)
	mac.Write([]byte(body))
	return base64.RawURLEncoding.EncodeToString([]byte(body)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyValue returns the username if the cookie body parses, the signature
// validates with constant-time compare, and the expiration is in the future.
// Returns "" on any failure.
func (a *Authenticator) verifyValue(v string) string {
	parts := strings.SplitN(v, ".", 2)
	if len(parts) != 2 {
		return ""
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return ""
	}
	gotSig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return ""
	}
	mac := hmac.New(sha256.New, a.key)
	mac.Write(body)
	if !hmac.Equal(gotSig, mac.Sum(nil)) {
		return ""
	}
	fields := strings.SplitN(string(body), "|", 2)
	if len(fields) != 2 {
		return ""
	}
	expUnix, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return ""
	}
	if time.Now().After(time.Unix(expUnix, 0)) {
		return ""
	}
	return fields[0]
}

// DefaultKeyPath returns the canonical location of the cookie HMAC key,
// honoring XDG_STATE_HOME when set.
func DefaultKeyPath() string {
	if xdg := os.Getenv("XDG_STATE_HOME"); xdg != "" {
		return filepath.Join(xdg, "braingler", "cookie.key")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "braingler-cookie.key"
	}
	return filepath.Join(home, ".local", "state", "braingler", "cookie.key")
}

func loadOrCreateKey(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		if len(b) < MinKeyBytes {
			return nil, fmt.Errorf("cookie key %s is too short (%d bytes; want >=%d). Delete it to regenerate", path, len(b), MinKeyBytes)
		}
		return b, nil
	}
	// Generate a fresh key.
	if dir := filepath.Dir(path); dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, fmt.Errorf("mkdir %s: %w", dir, err)
		}
	}
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate cookie key: %w", err)
	}
	if err := os.WriteFile(path, key, 0o600); err != nil {
		return nil, fmt.Errorf("write cookie key %s: %w", path, err)
	}
	return key, nil
}
