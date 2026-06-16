package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

const (
	ActionStatus       = "status"
	ActionWake         = "wake"
	ActionShutdown     = "shutdown"
	ActionSSHCert      = "ssh-cert"
	ActionCABootstrap  = "ca-bootstrap"
	ActionWildcard     = "*"
)

var validActions = map[string]bool{
	ActionStatus: true, ActionWake: true, ActionShutdown: true,
	ActionSSHCert: true, ActionCABootstrap: true,
}

const (
	CheckPing   = "ping"
	CheckUptime = "uptime"
	CheckLoad   = "load"
	CheckMemory = "memory"
	CheckDisk   = "disk"
)

var validChecks = map[string]bool{
	CheckPing: true, CheckUptime: true, CheckLoad: true,
	CheckMemory: true, CheckDisk: true,
}

type Config struct {
	Listen              Listen           `json:"listen"`
	PollIntervalSeconds int              `json:"poll_interval_seconds"`
	SSHDefaults         SSHConfig        `json:"ssh_defaults"`
	SSHCA               SSHCA            `json:"ssh_ca,omitempty"`
	Auth                Auth             `json:"auth"`
	Hosts               []Host           `json:"hosts"`
	hostByName          map[string]*Host `json:"-"`
}

// SSHCA configures braingler's SSH certificate authority. When Enabled,
// braingler signs short-lived user certs for itself, its agents, and any
// human who asks via /ssh-cert. When HostCAKeyFile is set, braingler also
// uses it to verify host certificates instead of trust-on-first-use.
type SSHCA struct {
	Enabled               bool   `json:"enabled"`
	KeyFile               string `json:"key_file,omitempty"`
	HostCAKeyFile         string `json:"host_ca_key_file,omitempty"`
	MaintenanceTTLSeconds int    `json:"maintenance_ttl_seconds,omitempty"`
	HumanTTLSeconds       int    `json:"human_ttl_seconds,omitempty"`
	AgentTTLSeconds       int    `json:"agent_ttl_seconds,omitempty"`
}

type Listen struct {
	Address string `json:"address,omitempty"`
	Socket  string `json:"socket,omitempty"`
}

type SSHConfig struct {
	User           string `json:"user,omitempty"`
	KeyFile        string `json:"key_file,omitempty"`
	Port           int    `json:"port,omitempty"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

type Auth struct {
	Enabled   bool             `json:"enabled"`
	Users     []User           `json:"users,omitempty"`
	APITokens []APIToken       `json:"api_tokens,omitempty"`
	Groups    map[string]Group `json:"groups,omitempty"`
}

type User struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Groups       []string `json:"groups"`
}

// APIToken is a non-human principal: a stored hash of a bearer token plus the
// groups that bearer is allowed to act as. The plaintext token is never
// retained — only its SHA-256 digest (high-entropy tokens don't need bcrypt).
type APIToken struct {
	Name      string   `json:"name"`
	TokenHash string   `json:"token_hash"` // "sha256:<hex>"
	Groups    []string `json:"groups"`
}

type Group struct {
	Hosts   []string `json:"hosts"`
	Actions []string `json:"actions"`
}

// PrincipalKind distinguishes how a request authenticated.
type PrincipalKind string

const (
	PrincipalUser  PrincipalKind = "user"
	PrincipalAgent PrincipalKind = "agent"
)

// Principal is the authenticated identity carried on a request. Users and
// agents share the groups/permission model but live in separate namespaces so
// a user named "claude-readonly" can't be confused with a token of that name.
type Principal struct {
	Name   string
	Kind   PrincipalKind
	Groups []string
}

type Host struct {
	Name            string           `json:"name"`
	DisplayName     string           `json:"display_name,omitempty"`
	Hostname        string           `json:"hostname"`
	MAC             string           `json:"mac"`
	Broadcast       string           `json:"broadcast"`
	MaintenanceUser string           `json:"maintenance_user,omitempty"` // overrides ssh_defaults.user for braingler's own SSH ops
	NoWake          bool             `json:"no_wake,omitempty"`          // forbid manual wake of this host (any caller, any auth mode)
	NoShutdown      bool             `json:"no_shutdown,omitempty"`      // forbid manual shutdown of this host (any caller, any auth mode)
	VerifyHostCert  bool             `json:"verify_host_cert,omitempty"` // require this host present a host cert signed by the host CA on braingler's own outbound SSH
	SSH             *SSHConfig       `json:"ssh,omitempty"`
	Checks          map[string]Check `json:"checks"`
}

type Check struct {
	Enabled bool `json:"enabled"`
	Every   int  `json:"every,omitempty"`
}

// Load reads, defaults, and validates a config file.
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	c := &Config{}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

func (c *Config) applyDefaults() {
	if c.PollIntervalSeconds == 0 {
		c.PollIntervalSeconds = 7
	}
	if c.SSHDefaults.Port == 0 {
		c.SSHDefaults.Port = 22
	}
	if c.SSHDefaults.TimeoutSeconds == 0 {
		c.SSHDefaults.TimeoutSeconds = 5
	}
	c.SSHDefaults.KeyFile = expandHome(c.SSHDefaults.KeyFile)
	if c.SSHCA.MaintenanceTTLSeconds == 0 {
		c.SSHCA.MaintenanceTTLSeconds = 300
	}
	if c.SSHCA.HumanTTLSeconds == 0 {
		c.SSHCA.HumanTTLSeconds = 86400
	}
	if c.SSHCA.AgentTTLSeconds == 0 {
		c.SSHCA.AgentTTLSeconds = 300
	}
	c.SSHCA.KeyFile = expandHome(c.SSHCA.KeyFile)
	c.SSHCA.HostCAKeyFile = expandHome(c.SSHCA.HostCAKeyFile)
	for i := range c.Hosts {
		h := &c.Hosts[i]
		if h.DisplayName == "" {
			h.DisplayName = h.Name
		}
		if h.SSH != nil {
			h.SSH.KeyFile = expandHome(h.SSH.KeyFile)
		}
		for name, chk := range h.Checks {
			if chk.Every <= 0 {
				chk.Every = 1
			}
			h.Checks[name] = chk
		}
	}
}

func (c *Config) validate() error {
	var errs []error

	switch {
	case c.Listen.Address == "" && c.Listen.Socket == "":
		errs = append(errs, errors.New("listen: must set address or socket"))
	case c.Listen.Address != "" && c.Listen.Socket != "":
		errs = append(errs, errors.New("listen: set only one of address or socket"))
	}

	if c.PollIntervalSeconds < 1 {
		errs = append(errs, fmt.Errorf("poll_interval_seconds: must be >= 1 (got %d)", c.PollIntervalSeconds))
	}

	if c.SSHCA.Enabled && c.SSHCA.KeyFile == "" {
		errs = append(errs, errors.New("ssh_ca.enabled but key_file is empty"))
	}

	c.hostByName = map[string]*Host{}
	for i := range c.Hosts {
		h := &c.Hosts[i]
		ctx := fmt.Sprintf("hosts[%d] (%s)", i, h.Name)
		if h.Name == "" {
			errs = append(errs, fmt.Errorf("hosts[%d]: name is required", i))
			continue
		}
		if _, dup := c.hostByName[h.Name]; dup {
			errs = append(errs, fmt.Errorf("%s: duplicate host name", ctx))
		}
		c.hostByName[h.Name] = h
		if h.Hostname == "" {
			errs = append(errs, fmt.Errorf("%s: hostname is required", ctx))
		}
		if _, err := net.ParseMAC(h.MAC); err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid MAC %q: %w", ctx, h.MAC, err))
		}
		if ip := net.ParseIP(h.Broadcast); ip == nil || ip.To4() == nil {
			errs = append(errs, fmt.Errorf("%s: invalid broadcast %q (need IPv4)", ctx, h.Broadcast))
		}
		for name := range h.Checks {
			if !validChecks[name] {
				errs = append(errs, fmt.Errorf("%s: unknown check %q (valid: ping, uptime, load, memory, disk)", ctx, name))
			}
		}
	}

	if c.Auth.Enabled {
		if len(c.Auth.Users) == 0 && len(c.Auth.APITokens) == 0 {
			errs = append(errs, errors.New("auth.enabled but no users or api_tokens defined"))
		}
		seenUser := map[string]bool{}
		for i, u := range c.Auth.Users {
			ctx := fmt.Sprintf("auth.users[%d] (%s)", i, u.Username)
			if u.Username == "" {
				errs = append(errs, fmt.Errorf("auth.users[%d]: username required", i))
				continue
			}
			if seenUser[u.Username] {
				errs = append(errs, fmt.Errorf("%s: duplicate username", ctx))
			}
			seenUser[u.Username] = true
			if u.PasswordHash == "" {
				errs = append(errs, fmt.Errorf("%s: password_hash required", ctx))
			}
			for _, g := range u.Groups {
				if _, ok := c.Auth.Groups[g]; !ok {
					errs = append(errs, fmt.Errorf("%s: references unknown group %q", ctx, g))
				}
			}
		}
		seenTok := map[string]bool{}
		for i, t := range c.Auth.APITokens {
			ctx := fmt.Sprintf("auth.api_tokens[%d] (%s)", i, t.Name)
			if t.Name == "" {
				errs = append(errs, fmt.Errorf("auth.api_tokens[%d]: name required", i))
				continue
			}
			if seenTok[t.Name] {
				errs = append(errs, fmt.Errorf("%s: duplicate token name", ctx))
			}
			seenTok[t.Name] = true
			if !strings.HasPrefix(t.TokenHash, "sha256:") || len(t.TokenHash) != len("sha256:")+64 {
				errs = append(errs, fmt.Errorf("%s: token_hash must be \"sha256:<64-hex-chars>\"", ctx))
			}
			if len(t.Groups) == 0 {
				errs = append(errs, fmt.Errorf("%s: at least one group required", ctx))
			}
			for _, g := range t.Groups {
				if _, ok := c.Auth.Groups[g]; !ok {
					errs = append(errs, fmt.Errorf("%s: references unknown group %q", ctx, g))
				}
			}
		}
		for name, g := range c.Auth.Groups {
			ctx := fmt.Sprintf("auth.groups[%s]", name)
			for _, h := range g.Hosts {
				if h == ActionWildcard {
					continue
				}
				if _, ok := c.hostByName[h]; !ok {
					errs = append(errs, fmt.Errorf("%s: references unknown host %q", ctx, h))
				}
			}
			for _, a := range g.Actions {
				if a == ActionWildcard {
					continue
				}
				if !validActions[a] {
					errs = append(errs, fmt.Errorf("%s: unknown action %q (valid: status, wake, shutdown)", ctx, a))
				}
			}
		}
	}

	return errors.Join(errs...)
}

// EffectiveSSH returns the host's SSH config merged over ssh_defaults.
func (c *Config) EffectiveSSH(h *Host) SSHConfig {
	out := c.SSHDefaults
	if h.SSH == nil {
		return out
	}
	if h.SSH.User != "" {
		out.User = h.SSH.User
	}
	if h.SSH.KeyFile != "" {
		out.KeyFile = h.SSH.KeyFile
	}
	if h.SSH.Port != 0 {
		out.Port = h.SSH.Port
	}
	if h.SSH.TimeoutSeconds != 0 {
		out.TimeoutSeconds = h.SSH.TimeoutSeconds
	}
	return out
}

// MaintenanceUser returns the username braingler should log in as for its own
// SSH ops against h, preferring per-host override then ssh_defaults.user.
func (c *Config) MaintenanceUser(h *Host) string {
	if h.MaintenanceUser != "" {
		return h.MaintenanceUser
	}
	return c.EffectiveSSH(h).User
}

// HostByName returns the host with the given name, or nil.
func (c *Config) HostByName(name string) *Host {
	return c.hostByName[name]
}

// UserCan reports whether the user (by username) is permitted to perform the
// given action on the given host. If auth is disabled this always returns true.
func (c *Config) UserCan(username, hostName, action string) bool {
	if c.HostActionForbidden(hostName, action) {
		return false
	}
	if !c.Auth.Enabled {
		return true
	}
	for _, u := range c.Auth.Users {
		if u.Username == username {
			return c.groupsCan(u.Groups, hostName, action)
		}
	}
	return false
}

// HostActionForbidden reports whether the host's OWN policy flags forbid the
// action, independent of who is asking and of whether auth is enabled. This is
// a host-level safety pin (no_wake / no_shutdown), not a permission grant — it
// can only deny. Checked first in every permission path so a pinned host's
// wake/shutdown buttons disappear and its API/CLI calls are refused even with
// auth off.
func (c *Config) HostActionForbidden(hostName, action string) bool {
	h := c.hostByName[hostName]
	if h == nil {
		return false
	}
	switch action {
	case ActionWake:
		return h.NoWake
	case ActionShutdown:
		return h.NoShutdown
	}
	return false
}

// PrincipalCan is the unified permission check across user and agent
// principals. Callers that already have a Principal handy should prefer this
// over UserCan — it avoids re-walking the user list per check.
func (c *Config) PrincipalCan(p Principal, hostName, action string) bool {
	if c.HostActionForbidden(hostName, action) {
		return false
	}
	if !c.Auth.Enabled {
		return true
	}
	return c.groupsCan(p.Groups, hostName, action)
}

// LookupUser returns the configured user record by username, or nil.
func (c *Config) LookupUser(username string) *User {
	for i, u := range c.Auth.Users {
		if u.Username == username {
			return &c.Auth.Users[i]
		}
	}
	return nil
}

// LookupAPIToken returns the configured agent token by name, or nil.
func (c *Config) LookupAPIToken(name string) *APIToken {
	for i, t := range c.Auth.APITokens {
		if t.Name == name {
			return &c.Auth.APITokens[i]
		}
	}
	return nil
}

func (c *Config) groupsCan(groups []string, hostName, action string) bool {
	for _, gname := range groups {
		g, ok := c.Auth.Groups[gname]
		if !ok {
			continue
		}
		if !slices.Contains(g.Hosts, hostName) && !slices.Contains(g.Hosts, ActionWildcard) {
			continue
		}
		if slices.Contains(g.Actions, action) || slices.Contains(g.Actions, ActionWildcard) {
			return true
		}
	}
	return false
}

// VisibleHosts returns the host names a principal is allowed to see (i.e. has
// status access on). Order matches the Hosts config slice.
func (c *Config) VisibleHosts(p Principal) []string {
	out := make([]string, 0, len(c.Hosts))
	for i := range c.Hosts {
		if c.PrincipalCan(p, c.Hosts[i].Name, ActionStatus) {
			out = append(out, c.Hosts[i].Name)
		}
	}
	return out
}

func expandHome(p string) string {
	if p == "" || !strings.HasPrefix(p, "~/") {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	return filepath.Join(home, p[2:])
}
