package sshx

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// Manager owns braingler's outbound SSH machinery. It supports both modes:
//
//   - Static-key mode (the original): each host's key_file authenticates
//     directly. Host keys are not verified.
//   - CA mode: braingler holds an ephemeral keypair, mints a short-lived
//     user certificate per (host, user) cached for `maintenance_ttl_seconds`,
//     and (for hosts with verify_host_cert set, when a host CA is loaded) uses
//     ssh.CertChecker to verify the host's certificate.
//
// One Manager exists per running braingler. It's safe for concurrent use.
type Manager struct {
	cfgPtr *config.Pointer
	userCA *sshca.CA // nil disables cert mode
	hostCA *sshca.CA // nil disables host-cert verification

	// In cert mode, braingler owns one in-memory Ed25519 keypair that every
	// minted cert is bound to. Restarting braingler rotates the key (and
	// invalidates all in-flight certs), which is exactly the lifecycle we
	// want for ephemeral material.
	maintSigner ssh.Signer

	mu    sync.Mutex
	cache map[string]cachedCert // key: hostName + "\x00" + user
}

type cachedCert struct {
	signer  ssh.Signer // ssh.NewCertSigner(cert, maintSigner)
	expires time.Time
}

// NewManager constructs a Manager. userCA may be nil to disable cert mode.
// hostCA may be nil to keep insecure-ignore host-key behavior.
func NewManager(cfgPtr *config.Pointer, userCA, hostCA *sshca.CA) (*Manager, error) {
	m := &Manager{
		cfgPtr: cfgPtr, userCA: userCA, hostCA: hostCA,
		cache: map[string]cachedCert{},
	}
	if userCA != nil {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("sshx: maintenance keypair: %w", err)
		}
		signer, err := ssh.NewSignerFromKey(priv)
		if err != nil {
			return nil, fmt.Errorf("sshx: wrap maintenance signer: %w", err)
		}
		m.maintSigner = signer
	}
	return m, nil
}

// cfg loads the current config snapshot. Read-only — never mutate the result.
func (m *Manager) cfg() *config.Config { return m.cfgPtr.Load() }

// MaintenancePublicKey returns the persistent SSH public key braingler will
// present (wrapped in a cert) for maintenance connections. Useful for
// diagnostics / "show me what to expect" output. Returns nil in static mode.
func (m *Manager) MaintenancePublicKey() ssh.PublicKey {
	if m.maintSigner == nil {
		return nil
	}
	return m.maintSigner.PublicKey()
}

// Dial opens an SSH connection to h. In CA mode this mints (or reuses) a
// short-lived user cert for the maintenance user; in static mode it falls
// back to the original key_file flow.
func (m *Manager) Dial(ctx context.Context, h *config.Host) (*Client, error) {
	if m.userCA == nil {
		// Static-key fallback — same path the package used pre-CA.
		return Dial(ctx, h.Hostname, m.cfg().EffectiveSSH(h))
	}
	user := m.cfg().MaintenanceUser(h)
	if user == "" {
		return nil, errors.New("sshx: maintenance user unset (set ssh_defaults.user or host.maintenance_user)")
	}
	certSigner, err := m.maintenanceCertSigner(h, user)
	if err != nil {
		return nil, err
	}
	return m.dialWithSigner(ctx, h, user, certSigner)
}

// Shutdown asks h to power off via sudo shutdown -hP now, using the same
// auth mode Dial would use.
func (m *Manager) Shutdown(ctx context.Context, h *config.Host) error {
	cli, err := m.Dial(ctx, h)
	if err != nil {
		return err
	}
	defer cli.Close()
	_, err = cli.Run("sudo -n shutdown -hP now")
	return err
}

// maintenanceCertSigner returns a signer that presents a current cert for
// (host, user). Cache hits avoid re-signing; misses (or expired entries)
// mint a fresh cert and replace the cache slot.
func (m *Manager) maintenanceCertSigner(h *config.Host, user string) (ssh.Signer, error) {
	key := h.Name + "\x00" + user
	now := time.Now()

	m.mu.Lock()
	c, ok := m.cache[key]
	m.mu.Unlock()
	// Renew when within half the original TTL of expiry so a long-running
	// session never bumps up against ValidBefore mid-connection.
	if ok && now.Add(time.Duration(m.cfg().SSHCA.MaintenanceTTLSeconds)*time.Second/2).Before(c.expires) {
		return c.signer, nil
	}

	ttl := time.Duration(m.cfg().SSHCA.MaintenanceTTLSeconds) * time.Second
	cert, err := m.userCA.SignUserCert(m.maintSigner.PublicKey(), sshca.UserCertOptions{
		KeyID:           fmt.Sprintf("maint host=%s user=%s", h.Name, user),
		ValidPrincipals: []string{user},
		TTL:             ttl,
		// No force-command — Unix permissions on the maintenance user are
		// the actual safety bound for this principal.
	})
	if err != nil {
		return nil, fmt.Errorf("sshx: sign maintenance cert: %w", err)
	}
	certSigner, err := ssh.NewCertSigner(cert, m.maintSigner)
	if err != nil {
		return nil, fmt.Errorf("sshx: wrap cert signer: %w", err)
	}

	m.mu.Lock()
	m.cache[key] = cachedCert{signer: certSigner, expires: now.Add(ttl)}
	m.mu.Unlock()
	return certSigner, nil
}

// dialWithSigner is the cert-mode connection path. Mirrors the structure of
// the original Dial but plugs in an arbitrary signer and a host-key callback
// that honors the host CA when configured.
func (m *Manager) dialWithSigner(ctx context.Context, h *config.Host, user string, signer ssh.Signer) (*Client, error) {
	eff := m.cfg().EffectiveSSH(h)
	if eff.Port == 0 {
		eff.Port = 22
	}
	if eff.TimeoutSeconds == 0 {
		eff.TimeoutSeconds = 5
	}
	timeout := time.Duration(eff.TimeoutSeconds) * time.Second

	sshCfg := &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: m.hostKeyCallback(h),
		Timeout:         timeout,
	}

	addr := net.JoinHostPort(h.Hostname, strconv.Itoa(eff.Port))
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("ssh: dial %s: %w", addr, err)
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, sshCfg)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("ssh: handshake %s: %w", addr, err)
	}
	return &Client{cli: ssh.NewClient(c, chans, reqs)}, nil
}

// hostKeyCallback returns an ssh.HostKeyCallback for connecting to h. Host-cert
// verification is OPT-IN per host: it requires both a configured host CA AND
// h.verify_host_cert. Otherwise it falls back to "trust on first sight" (no
// verification) — preserving the default behavior, and letting a cert-less host
// (one not yet issued a host cert) stay reachable even when the CA is loaded.
// ssh.CertChecker validates the cert's principals against the address dialed.
func (m *Manager) hostKeyCallback(h *config.Host) ssh.HostKeyCallback {
	if m.hostCA == nil || !h.VerifyHostCert {
		return ssh.InsecureIgnoreHostKey()
	}
	checker := &ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, _ string) bool {
			return string(auth.Marshal()) == string(m.hostCA.PublicKey().Marshal())
		},
		// HostKeyFallback fires when the host presents a plain key instead
		// of a cert. We reject in that case — this host opted in to
		// verify_host_cert, so it's expected to present a cert.
		HostKeyFallback: func(addr string, _ net.Addr, _ ssh.PublicKey) error {
			return fmt.Errorf("ssh: %s did not present a host certificate (expected one signed by %s)",
				addr, m.hostCA.Fingerprint())
		},
	}
	return checker.CheckHostKey
}
