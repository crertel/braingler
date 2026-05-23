package auth

import (
	"strings"
	"testing"

	"github.com/crertel/braingler/internal/config"
)

func TestMintAndVerifyRoundTrip(t *testing.T) {
	tok, hash, err := MintToken()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(tok, TokenPrefix) {
		t.Errorf("token missing prefix: %q", tok)
	}
	if !strings.HasPrefix(hash, "sha256:") || len(hash) != len("sha256:")+64 {
		t.Errorf("hash shape wrong: %q", hash)
	}
	if HashToken(tok) != hash {
		t.Error("HashToken not deterministic")
	}

	cfg := &config.Config{Auth: config.Auth{Enabled: true, APITokens: []config.APIToken{
		{Name: "claude-readonly", TokenHash: hash, Groups: []string{"agent"}},
	}}}
	got, err := VerifyToken(cfg, tok)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if got.Name != "claude-readonly" {
		t.Errorf("got name %q", got.Name)
	}
}

func TestVerifyRejectsUnknown(t *testing.T) {
	cfg := &config.Config{Auth: config.Auth{Enabled: true, APITokens: []config.APIToken{
		{Name: "claude", TokenHash: HashToken("bglr_realtoken"), Groups: []string{"agent"}},
	}}}
	if _, err := VerifyToken(cfg, "bglr_wrongtoken"); !IsInvalidToken(err) {
		t.Errorf("got %v, want invalid token", err)
	}
	if _, err := VerifyToken(cfg, ""); !IsInvalidToken(err) {
		t.Errorf("empty token should be invalid, got %v", err)
	}
}

func TestPresentedBearer(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"Bearer abc", "abc"},
		{"Bearer   abc  ", "abc"},
		{"bearer abc", ""}, // case-sensitive scheme name, fine for now
		{"Basic abc", ""},
		{"", ""},
	}
	for _, tt := range tests {
		if got := PresentedBearer(tt.in); got != tt.want {
			t.Errorf("PresentedBearer(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestMintProducesDifferentTokens(t *testing.T) {
	t1, _, _ := MintToken()
	t2, _, _ := MintToken()
	if t1 == t2 {
		t.Error("two mints produced identical tokens")
	}
}
