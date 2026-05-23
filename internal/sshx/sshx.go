// Package sshx wraps golang.org/x/crypto/ssh with the patterns braingler
// needs: key-file auth, short-lived connections per command, host-key policy
// suitable for a homelab (insecure-but-explicit).
package sshx

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/crertel/braingler/internal/config"
	"golang.org/x/crypto/ssh"
)

// Client is a short-lived ssh.Client wrapper. Construct one per logical
// operation; commands that take longer than the configured timeout will be
// killed when the connection closes.
type Client struct {
	cli *ssh.Client
}

// Dial connects to host using the merged ssh config (host overrides over
// defaults — caller is responsible for merging via config.EffectiveSSH).
//
// Host-key checking is disabled (InsecureIgnoreHostKey). For a homelab on a
// trusted LAN this is the usual trade-off — if you need stricter checking,
// swap in a known_hosts-backed callback.
func Dial(ctx context.Context, hostname string, cfg config.SSHConfig) (*Client, error) {
	if cfg.User == "" {
		return nil, errors.New("ssh: user not set")
	}
	if cfg.KeyFile == "" {
		return nil, errors.New("ssh: key_file not set")
	}

	keyBytes, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("ssh: read key %s: %w", cfg.KeyFile, err)
	}
	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("ssh: parse key %s: %w", cfg.KeyFile, err)
	}

	timeout := time.Duration(cfg.TimeoutSeconds) * time.Second
	sshCfg := &ssh.ClientConfig{
		User:            cfg.User,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         timeout,
	}

	addr := net.JoinHostPort(hostname, strconv.Itoa(cfg.Port))
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

func (c *Client) Close() error { return c.cli.Close() }

// Run executes cmd and returns its stdout. Stderr is captured separately and
// folded into the error on non-zero exit so callers see *why* a command failed.
func (c *Client) Run(cmd string) (string, error) {
	sess, err := c.cli.NewSession()
	if err != nil {
		return "", fmt.Errorf("ssh: session: %w", err)
	}
	defer sess.Close()

	var stderr bytes.Buffer
	sess.Stderr = &stderr
	out, err := sess.Output(cmd)
	if err != nil {
		var ee *ssh.ExitError
		if errors.As(err, &ee) {
			return string(out), fmt.Errorf("ssh: %q exit %d: %s",
				cmd, ee.ExitStatus(), strings.TrimSpace(stderr.String()))
		}
		return string(out), fmt.Errorf("ssh: %q: %w", cmd, err)
	}
	return string(out), nil
}

// Shutdown asks the host to power off via `sudo -n shutdown -hP now`. The
// `-n` makes sudo fail loudly rather than prompt for a password — the user's
// sudoers must allow the configured user to run shutdown without a password.
//
// In practice `shutdown` schedules the halt and exits 0 promptly, so this
// returns nil shortly after the command runs; the host itself goes down a
// few seconds later. Surfaces sudo/auth failures so the caller knows the
// command never took.
func Shutdown(ctx context.Context, hostname string, cfg config.SSHConfig) error {
	cli, err := Dial(ctx, hostname, cfg)
	if err != nil {
		return err
	}
	defer cli.Close()
	_, err = cli.Run("sudo -n shutdown -hP now")
	return err
}
