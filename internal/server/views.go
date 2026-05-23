package server

import (
	"fmt"
	"html/template"
	"time"

	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/hosts"
)

// hostView is the per-card view model: a small façade over (config.Host,
// hosts.Status) that exposes booleans and formatted strings the templates
// can use without ad-hoc math.
type hostView struct {
	Name              string
	DisplayName       string
	Hostname          string
	Reachable         string
	IsUp              bool
	LastErr           string
	LastCheckedPretty string
	HasUptime         bool
	UptimePretty      string
	HasLoad           bool
	LoadPretty        string
	HasMemory         bool
	MemoryPretty      string
	Disks             []hosts.DiskInfo
	ShowStats         bool
	PollSeconds       int
	CanWake           bool
	CanShutdown       bool
}

func newHostView(h *config.Host, st hosts.Status, pollSec int, canWake, canShutdown bool) hostView {
	v := hostView{
		Name:        h.Name,
		DisplayName: h.DisplayName,
		Hostname:    h.Hostname,
		Reachable:   st.Reachable.String(),
		IsUp:        st.Reachable == hosts.Up,
		LastErr:     st.LastErr,
		PollSeconds: pollSec,
		CanWake:     canWake,
		CanShutdown: canShutdown,
	}
	if !st.LastChecked.IsZero() {
		v.LastCheckedPretty = humanAgo(st.LastChecked)
	}
	if st.Uptime > 0 {
		v.HasUptime = true
		v.UptimePretty = humanDuration(st.Uptime)
	}
	if st.Load != (hosts.LoadInfo{}) {
		v.HasLoad = true
		v.LoadPretty = fmt.Sprintf("%.2f  %.2f  %.2f", st.Load.One, st.Load.Five, st.Load.Fifteen)
	}
	if st.Memory.TotalKB > 0 {
		v.HasMemory = true
		v.MemoryPretty = formatMemory(st.Memory)
	}
	v.Disks = st.Disks
	v.ShowStats = v.HasUptime || v.HasLoad || v.HasMemory || len(v.Disks) > 0
	return v
}

// humanDuration formats a duration as the largest two units that fit, e.g.
// "3d 4h", "12h 30m", "45m 20s", "12s".
func humanDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	mins := int(d / time.Minute)
	d -= time.Duration(mins) * time.Minute
	secs := int(d / time.Second)

	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, hours)
	case hours > 0:
		return fmt.Sprintf("%dh %dm", hours, mins)
	case mins > 0:
		return fmt.Sprintf("%dm %ds", mins, secs)
	default:
		return fmt.Sprintf("%ds", secs)
	}
}

// humanAgo formats "time since t" in compact form: "3s ago", "2m ago", etc.
func humanAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds ago", int(d/time.Second))
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d/time.Minute))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d/time.Hour))
	default:
		return fmt.Sprintf("%dd ago", int(d/(24*time.Hour)))
	}
}

// formatMemory renders memory as "used/total GiB (pct%)".
func formatMemory(m hosts.MemInfo) string {
	usedKB := max(m.TotalKB-m.AvailableKB, 0)
	pct := 0
	if m.TotalKB > 0 {
		pct = (usedKB * 100) / m.TotalKB
	}
	return fmt.Sprintf("%.1f / %.1f GiB (%d%%)",
		float64(usedKB)/1024/1024,
		float64(m.TotalKB)/1024/1024,
		pct)
}

// templateFuncs is empty for now — all derived values are pre-computed on the
// view. Keeping the hook so step 7 (SSE) can plug things in without churn.
var templateFuncs = template.FuncMap{}
