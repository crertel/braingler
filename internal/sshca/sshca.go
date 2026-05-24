// Package sshca implements braingler's SSH certificate authority.
//
// Two CA roles are supported:
//
//   - User CA: signs SSH user certificates. Hosts trust this CA via
//     TrustedUserCAKeys in sshd_config; principals on the cert become valid
//     login names.
//
//   - Host CA: signs SSH host certificates. Clients (i.e. braingler itself)
//     trust this CA via @cert-authority entries in known_hosts; sshd presents
//     the host cert at connection time.
//
// Both roles use Ed25519 keys. The CA private keys live on disk in OpenSSH
// PEM format with mode 0600. If asked to load a CA whose file does not exist,
// Load generates one — mirroring the cookie-key bootstrap.
package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

// CA wraps a single CA keypair with helpers for signing user and host certs.
// One CA can be used for both roles in a small deployment; larger setups
// should use separate User and Host CAs.
type CA struct {
	signer  ssh.Signer
	keyPath string
}

// Load reads a CA from path, generating one if the file does not exist.
// The generated key is Ed25519 in OpenSSH PEM format, written with mode 0600.
func Load(path string) (*CA, error) {
	if path == "" {
		return nil, errors.New("sshca: empty key path")
	}
	if _, err := os.Stat(path); os.IsNotExist(err) {
		if err := generate(path); err != nil {
			return nil, fmt.Errorf("sshca: generate %s: %w", path, err)
		}
	}
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("sshca: read %s: %w", path, err)
	}
	signer, err := ssh.ParsePrivateKey(pem)
	if err != nil {
		return nil, fmt.Errorf("sshca: parse %s: %w", path, err)
	}
	return &CA{signer: signer, keyPath: path}, nil
}

// PublicKey returns the CA's public key.
func (c *CA) PublicKey() ssh.PublicKey { return c.signer.PublicKey() }

// AuthorizedKey is the CA pubkey in `ssh-ed25519 AAAA... <comment>` form,
// suitable for pasting into TrustedUserCAKeys or @cert-authority lines.
func (c *CA) AuthorizedKey(comment string) string {
	line := string(ssh.MarshalAuthorizedKey(c.PublicKey()))
	// MarshalAuthorizedKey already includes a trailing newline; we add the
	// comment on the same line by trimming it first.
	line = line[:len(line)-1]
	if comment != "" {
		line += " " + comment
	}
	return line
}

// Fingerprint returns a short SHA-256 fingerprint for log/UI display.
func (c *CA) Fingerprint() string {
	sum := sha256.Sum256(c.PublicKey().Marshal())
	return "SHA256:" + hex.EncodeToString(sum[:8])
}

// UserCertOptions controls how SignUserCert builds the certificate. Empty
// or zero fields use sensible defaults.
type UserCertOptions struct {
	// KeyID is the cert's identifier — embedded in sshd logs and useful for
	// audit. A good value bakes in actor + action + correlation, e.g.
	// "actor=claude-ro action=shutdown action_id=abc123".
	KeyID string
	// ValidPrincipals are the login names the cert is valid for. At least
	// one must be supplied.
	ValidPrincipals []string
	// TTL is how long the cert is valid for. Defaults to 5 minutes if zero.
	TTL time.Duration
	// ForceCommand pins the cert to a single command via the force-command
	// critical option. Leave empty for interactive (human) certs.
	ForceCommand string
	// NoPTY, NoPortForwarding, NoX11Forwarding, NoAgentForwarding tighten
	// what the cert can do. Default false (= permitted) preserves typical
	// shell usability for humans; the agent path sets all to true.
	NoPTY             bool
	NoPortForwarding  bool
	NoX11Forwarding   bool
	NoAgentForwarding bool
}

// SignUserCert signs userKey, returning the certificate. The caller passes
// in the principal's public key — braingler never sees the principal's
// private key.
func (c *CA) SignUserCert(userKey ssh.PublicKey, opts UserCertOptions) (*ssh.Certificate, error) {
	if len(opts.ValidPrincipals) == 0 {
		return nil, errors.New("sshca: SignUserCert needs at least one principal")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	now := time.Now()

	cert := &ssh.Certificate{
		Key:             userKey,
		CertType:        ssh.UserCert,
		KeyId:           opts.KeyID,
		ValidPrincipals: opts.ValidPrincipals,
		ValidAfter:      uint64(now.Add(-30 * time.Second).Unix()), // small skew tolerance
		ValidBefore:     uint64(now.Add(ttl).Unix()),
		Permissions:     buildPermissions(opts),
	}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return nil, fmt.Errorf("sshca: sign user cert: %w", err)
	}
	return cert, nil
}

func buildPermissions(opts UserCertOptions) ssh.Permissions {
	p := ssh.Permissions{
		CriticalOptions: map[string]string{},
		Extensions:      map[string]string{},
	}
	if opts.ForceCommand != "" {
		p.CriticalOptions["force-command"] = opts.ForceCommand
	}
	if !opts.NoPTY {
		p.Extensions["permit-pty"] = ""
	}
	if !opts.NoPortForwarding {
		p.Extensions["permit-port-forwarding"] = ""
	}
	if !opts.NoX11Forwarding {
		p.Extensions["permit-X11-forwarding"] = ""
	}
	if !opts.NoAgentForwarding {
		p.Extensions["permit-agent-forwarding"] = ""
	}
	return p
}

// HostCertOptions controls SignHostCert.
type HostCertOptions struct {
	// KeyID identifies the cert in sshd logs (e.g. the host name).
	KeyID string
	// ValidPrincipals are the hostnames clients may use to reach the host
	// (e.g. ["lab-host", "lab-host.local", "192.168.1.42"]).
	ValidPrincipals []string
	// TTL defaults to 52 weeks if zero — host certs rotate rarely.
	TTL time.Duration
}

// SignHostCert signs hostKey as a host certificate.
func (c *CA) SignHostCert(hostKey ssh.PublicKey, opts HostCertOptions) (*ssh.Certificate, error) {
	if len(opts.ValidPrincipals) == 0 {
		return nil, errors.New("sshca: SignHostCert needs at least one principal")
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = 52 * 7 * 24 * time.Hour
	}
	now := time.Now()
	cert := &ssh.Certificate{
		Key:             hostKey,
		CertType:        ssh.HostCert,
		KeyId:           opts.KeyID,
		ValidPrincipals: opts.ValidPrincipals,
		ValidAfter:      uint64(now.Add(-30 * time.Second).Unix()),
		ValidBefore:     uint64(now.Add(ttl).Unix()),
	}
	if err := cert.SignCert(rand.Reader, c.signer); err != nil {
		return nil, fmt.Errorf("sshca: sign host cert: %w", err)
	}
	return cert, nil
}

// MarshalCertificate is a small wrapper that produces a one-line authorized
// cert blob (`ssh-ed25519-cert-v01@openssh.com AAAA... <comment>`).
func MarshalCertificate(cert *ssh.Certificate, comment string) string {
	line := string(ssh.MarshalAuthorizedKey(cert))
	line = line[:len(line)-1] // strip newline
	if comment != "" {
		line += " " + comment
	}
	return line
}

// GenerateEphemeralUserKeypair creates a fresh Ed25519 keypair for use by an
// agent that doesn't already have one. Returns (privatePEM, sshPublicKey).
func GenerateEphemeralUserKeypair() (privatePEM []byte, publicKey ssh.PublicKey, err error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("sshca: ephemeral keygen: %w", err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "braingler ephemeral")
	if err != nil {
		return nil, nil, fmt.Errorf("sshca: marshal ephemeral: %w", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("sshca: wrap ephemeral pubkey: %w", err)
	}
	return pem.EncodeToMemory(block), sshPub, nil
}

// generate creates a fresh Ed25519 CA key at path with mode 0600.
func generate(path string) error {
	if dir := filepath.Dir(path); dir != "." && dir != "/" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err
		}
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(priv, "braingler CA")
	if err != nil {
		return err
	}
	return os.WriteFile(path, pem.EncodeToMemory(block), 0o600)
}
