package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/crertel/braingler/internal/config"
)

// TokenPrefix is prepended to issued tokens so they're recognizable at a
// glance ("looks like a braingler token") and to make a future migration to
// a different scheme easy by version-bumping the prefix.
const TokenPrefix = "bglr_"

// MintToken generates a new bearer token. The returned token is what the
// agent sends in `Authorization: Bearer <token>`; hash is the value to store
// in config (always "sha256:<hex>"). The plaintext token is shown to the
// user exactly once.
func MintToken() (token, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("mint: %w", err)
	}
	token = TokenPrefix + base64.RawURLEncoding.EncodeToString(buf)
	hash = HashToken(token)
	return token, hash, nil
}

// HashToken hashes a token in its on-wire form. The hash format mirrors what
// the validator stores in config.json: "sha256:<lowercase hex>".
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "sha256:" + hex.EncodeToString(sum[:])
}

// VerifyToken resolves a bearer token to the matching APIToken record using a
// constant-time compare. Returns (nil, errInvalidToken) if no entry matches.
func VerifyToken(cfg *config.Config, presented string) (*config.APIToken, error) {
	if presented == "" {
		return nil, errInvalidToken
	}
	got := HashToken(presented)
	for i := range cfg.Auth.APITokens {
		t := &cfg.Auth.APITokens[i]
		if subtle.ConstantTimeCompare([]byte(t.TokenHash), []byte(got)) == 1 {
			return t, nil
		}
	}
	return nil, errInvalidToken
}

// PresentedBearer extracts the bearer credential from an Authorization
// header. Returns "" if the header is missing or not a Bearer scheme.
func PresentedBearer(authHeader string) string {
	const prefix = "Bearer "
	if !strings.HasPrefix(authHeader, prefix) {
		return ""
	}
	return strings.TrimSpace(authHeader[len(prefix):])
}

var errInvalidToken = errors.New("invalid api token")

// IsInvalidToken reports whether err came from a failed token check.
func IsInvalidToken(err error) bool { return errors.Is(err, errInvalidToken) }
