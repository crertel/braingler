package auth

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/crertel/braingler/internal/config"
	"golang.org/x/crypto/bcrypt"
)

func newTestAuth(t *testing.T, users []config.User) *Authenticator {
	t.Helper()
	cfg := &config.Config{Auth: config.Auth{Enabled: true, Users: users}}
	keyPath := filepath.Join(t.TempDir(), "cookie.key")
	a, err := New(cfg, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func hashPw(t *testing.T, s string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(s), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}

func TestVerifyCredentialsOK(t *testing.T) {
	a := newTestAuth(t, []config.User{{Username: "alice", PasswordHash: hashPw(t, "secret")}})
	if err := a.VerifyCredentials("alice", "secret"); err != nil {
		t.Errorf("unexpected: %v", err)
	}
}

func TestVerifyCredentialsBadPassword(t *testing.T) {
	a := newTestAuth(t, []config.User{{Username: "alice", PasswordHash: hashPw(t, "secret")}})
	if err := a.VerifyCredentials("alice", "wrong"); !IsInvalidCredentials(err) {
		t.Errorf("got %v, want invalid credentials", err)
	}
}

func TestVerifyCredentialsUnknownUser(t *testing.T) {
	a := newTestAuth(t, []config.User{{Username: "alice", PasswordHash: hashPw(t, "secret")}})
	if err := a.VerifyCredentials("ghost", "secret"); !IsInvalidCredentials(err) {
		t.Errorf("got %v, want invalid credentials", err)
	}
}

func TestCookieRoundTrip(t *testing.T) {
	a := newTestAuth(t, nil)
	c := a.IssueCookie("alice")

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	if got := a.UserFromRequest(req); got != "alice" {
		t.Errorf("UserFromRequest = %q, want alice", got)
	}
}

func TestCookieTamperingRejected(t *testing.T) {
	a := newTestAuth(t, nil)
	c := a.IssueCookie("alice")
	c.Value += "x" // corrupt the signature

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	if got := a.UserFromRequest(req); got != "" {
		t.Errorf("tampered cookie should not authenticate, got %q", got)
	}
}

func TestCookieDifferentSecretRejected(t *testing.T) {
	a1 := newTestAuth(t, nil)
	a2 := newTestAuth(t, nil) // different temp key
	c := a1.IssueCookie("alice")

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	if got := a2.UserFromRequest(req); got != "" {
		t.Errorf("cookie from foreign key should not authenticate, got %q", got)
	}
}

func TestCookieExpiry(t *testing.T) {
	a := newTestAuth(t, nil)
	a.ttl = -1 * time.Hour // already expired
	c := a.IssueCookie("alice")

	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	if got := a.UserFromRequest(req); got != "" {
		t.Errorf("expired cookie should not authenticate, got %q", got)
	}
}

func TestNoCookieReturnsEmpty(t *testing.T) {
	a := newTestAuth(t, nil)
	req := httptest.NewRequest("GET", "/", nil)
	if got := a.UserFromRequest(req); got != "" {
		t.Errorf("got %q, want empty", got)
	}
}

func TestKeyPersistsAcrossLoads(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "cookie.key")
	cfg := &config.Config{Auth: config.Auth{Enabled: true}}

	a1, err := New(cfg, keyPath)
	if err != nil {
		t.Fatal(err)
	}
	a2, err := New(cfg, keyPath) // should reuse the file written by a1
	if err != nil {
		t.Fatal(err)
	}
	c := a1.IssueCookie("alice")
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(c)
	if got := a2.UserFromRequest(req); got != "alice" {
		t.Errorf("reloaded key should validate sibling-issued cookie, got %q", got)
	}
	// And: HttpOnly + SameSite are set
	if c.HttpOnly != true || c.SameSite != http.SameSiteLaxMode {
		t.Errorf("cookie security attrs missing: %+v", c)
	}
}
