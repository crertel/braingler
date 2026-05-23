// Package monitor runs the background poll loop and writes results into the
// hosts.Registry. Each configured host gets its own goroutine.
package monitor

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/hosts"
	"github.com/crertel/braingler/internal/sshx"
)

type Monitor struct {
	cfg      *config.Config
	registry *hosts.Registry
	logger   *slog.Logger
}

func New(cfg *config.Config, reg *hosts.Registry, logger *slog.Logger) *Monitor {
	if logger == nil {
		logger = slog.Default()
	}
	return &Monitor{cfg: cfg, registry: reg, logger: logger}
}

// Run blocks until ctx is canceled, polling every host on its own schedule.
func (m *Monitor) Run(ctx context.Context) {
	for i := range m.cfg.Hosts {
		m.registry.Register(m.cfg.Hosts[i].Name)
	}

	var wg sync.WaitGroup
	for i := range m.cfg.Hosts {
		h := &m.cfg.Hosts[i]
		wg.Go(func() { m.runHost(ctx, h) })
	}
	wg.Wait()
}

func (m *Monitor) runHost(ctx context.Context, h *config.Host) {
	interval := time.Duration(m.cfg.PollIntervalSeconds) * time.Second
	log := m.logger.With("host", h.Name)

	// tick counts checkOnce invocations starting at 1, so a check with
	// `every: N` first runs on tick N and every N ticks thereafter.
	tick := 0
	for {
		tick++
		m.checkOnce(ctx, h, tick, log)
		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
		}
	}
}

func (m *Monitor) checkOnce(ctx context.Context, h *config.Host, tick int, log *slog.Logger) {
	// 1) Ping is the source of truth for up/down. If it's disabled we still
	//    do nothing — ping is what gates SSH checks below.
	if !h.Checks[config.CheckPing].Enabled {
		return
	}

	now := time.Now()
	reachable, err := Ping(ctx, h.Hostname)
	prev, _ := m.registry.Update(h.Name, func(s *hosts.Status) {
		s.LastChecked = now
		switch {
		case err != nil:
			s.Reachable = hosts.Unknown
			s.LastErr = err.Error()
		case reachable:
			s.Reachable = hosts.Up
			s.LastErr = ""
		default:
			s.Reachable = hosts.Down
			s.LastErr = ""
			// Clear stale SSH-derived fields when the host goes down.
			s.Uptime = 0
			s.Load = hosts.LoadInfo{}
			s.Memory = hosts.MemInfo{}
			s.Disks = nil
		}
	})
	if cur, _ := m.registry.Get(h.Name); cur.Reachable != prev {
		log.Info("state change", "from", prev.String(), "to", cur.Reachable.String(), "err", cur.LastErr)
	}

	// 2) SSH checks. Skip unless host is reachable.
	if !reachable {
		return
	}
	todo := dueSSHChecks(h, tick)
	if len(todo) == 0 {
		return
	}
	m.runSSHChecks(ctx, h, todo, log)
}

// dueSSHChecks returns the enabled SSH-based check names that should fire on
// this tick (i.e. tick % every == 0). Ping is excluded — it runs separately.
func dueSSHChecks(h *config.Host, tick int) []string {
	var out []string
	for _, name := range []string{config.CheckUptime, config.CheckLoad, config.CheckMemory, config.CheckDisk} {
		chk := h.Checks[name]
		if !chk.Enabled {
			continue
		}
		every := max(chk.Every, 1)
		if tick%every == 0 {
			out = append(out, name)
		}
	}
	return out
}

// runSSHChecks opens one SSH connection and runs the listed checks over it.
// Each check is independent: a failure of one is logged but doesn't abort
// the others.
func (m *Monitor) runSSHChecks(ctx context.Context, h *config.Host, todo []string, log *slog.Logger) {
	cli, err := sshx.Dial(ctx, h.Hostname, m.cfg.EffectiveSSH(h))
	if err != nil {
		log.Warn("ssh dial failed", "err", err)
		m.registry.Update(h.Name, func(s *hosts.Status) { s.LastErr = err.Error() })
		return
	}
	defer cli.Close()

	for _, name := range todo {
		if err := m.runOneCheck(cli, h.Name, name); err != nil {
			log.Warn("ssh check failed", "check", name, "err", err)
		}
	}
}

func (m *Monitor) runOneCheck(cli *sshx.Client, hostName, checkName string) error {
	switch checkName {
	case config.CheckUptime:
		out, err := cli.Run("cat /proc/uptime")
		if err != nil {
			return err
		}
		d, err := parseUptime(out)
		if err != nil {
			return err
		}
		m.registry.Update(hostName, func(s *hosts.Status) { s.Uptime = d })

	case config.CheckLoad:
		out, err := cli.Run("cat /proc/loadavg")
		if err != nil {
			return err
		}
		l, err := parseLoad(out)
		if err != nil {
			return err
		}
		m.registry.Update(hostName, func(s *hosts.Status) { s.Load = l })

	case config.CheckMemory:
		out, err := cli.Run("cat /proc/meminfo")
		if err != nil {
			return err
		}
		mi, err := parseMemInfo(out)
		if err != nil {
			return err
		}
		m.registry.Update(hostName, func(s *hosts.Status) { s.Memory = mi })

	case config.CheckDisk:
		out, err := cli.Run("df --output=target,fstype,pcent")
		if err != nil {
			return err
		}
		d, err := parseDfOutput(out)
		if err != nil {
			return err
		}
		m.registry.Update(hostName, func(s *hosts.Status) { s.Disks = d })
	}
	return nil
}
