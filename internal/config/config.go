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
	ActionStatus   = "status"
	ActionWake     = "wake"
	ActionShutdown = "shutdown"
	ActionWildcard = "*"
)

var validActions = map[string]bool{
	ActionStatus: true, ActionWake: true, ActionShutdown: true,
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
	Auth                Auth             `json:"auth"`
	Hosts               []Host           `json:"hosts"`
	hostByName          map[string]*Host `json:"-"`
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
	Enabled bool             `json:"enabled"`
	Users   []User           `json:"users,omitempty"`
	Groups  map[string]Group `json:"groups,omitempty"`
}

type User struct {
	Username     string   `json:"username"`
	PasswordHash string   `json:"password_hash"`
	Groups       []string `json:"groups"`
}

type Group struct {
	Hosts   []string `json:"hosts"`
	Actions []string `json:"actions"`
}

type Host struct {
	Name        string           `json:"name"`
	DisplayName string           `json:"display_name,omitempty"`
	Hostname    string           `json:"hostname"`
	MAC         string           `json:"mac"`
	Broadcast   string           `json:"broadcast"`
	SSH         *SSHConfig       `json:"ssh,omitempty"`
	Checks      map[string]Check `json:"checks"`
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
		if len(c.Auth.Users) == 0 {
			errs = append(errs, errors.New("auth.enabled but no users defined"))
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

// HostByName returns the host with the given name, or nil.
func (c *Config) HostByName(name string) *Host {
	return c.hostByName[name]
}

// UserCan reports whether the user (by username) is permitted to perform the
// given action on the given host. If auth is disabled this always returns true.
func (c *Config) UserCan(username, hostName, action string) bool {
	if !c.Auth.Enabled {
		return true
	}
	var groups []string
	for _, u := range c.Auth.Users {
		if u.Username == username {
			groups = u.Groups
			break
		}
	}
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
