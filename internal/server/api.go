package server

import (
	"net/http"
	"time"

	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/hosts"
)

// API response types live here in one place so the OpenAPI spec (step 5) can
// reference them by name and the hand-written JSON shapes stay aligned.

// apiHost is one host as the API reports it.
type apiHost struct {
	Name        string           `json:"name"`
	DisplayName string           `json:"display_name"`
	Hostname    string           `json:"hostname"`
	MAC         string           `json:"mac"`
	Broadcast   string           `json:"broadcast"`
	Status      apiStatus        `json:"status"`
	Permissions apiPermissions   `json:"permissions"`
	Checks      []apiCheckConfig `json:"checks"`
}

type apiStatus struct {
	Reachable   string         `json:"reachable"`            // "up" | "down" | "unknown"
	LastChecked *time.Time     `json:"last_checked,omitempty"`
	LastChange  *time.Time     `json:"last_change,omitempty"`
	LastError   string         `json:"last_error,omitempty"`
	UptimeSec   *int64         `json:"uptime_seconds,omitempty"`
	Load        *apiLoad       `json:"load,omitempty"`
	Memory      *apiMemory     `json:"memory,omitempty"`
	Disks       []apiDisk      `json:"disks,omitempty"`
}

type apiLoad struct {
	One     float64 `json:"one"`
	Five    float64 `json:"five"`
	Fifteen float64 `json:"fifteen"`
}

type apiMemory struct {
	TotalKB     int `json:"total_kb"`
	AvailableKB int `json:"available_kb"`
	UsedPct     int `json:"used_pct"`
}

type apiDisk struct {
	Mount   string `json:"mount"`
	FSType  string `json:"fstype"`
	UsedPct int    `json:"used_pct"`
}

type apiPermissions struct {
	CanStatus   bool `json:"can_status"`
	CanWake     bool `json:"can_wake"`
	CanShutdown bool `json:"can_shutdown"`
}

type apiCheckConfig struct {
	Name    string `json:"name"`
	Enabled bool   `json:"enabled"`
	Every   int    `json:"every"`
}

type apiWhoami struct {
	Name     string   `json:"name"`
	Kind     string   `json:"kind"` // "user" | "agent" | "anonymous"
	Groups   []string `json:"groups"`
	Hosts    []string `json:"hosts"`
	AuthMode string   `json:"auth_mode"` // "cookie" | "bearer" | "disabled"
}

type apiHostList struct {
	Hosts []apiHost `json:"hosts"`
}

// --- handlers ---------------------------------------------------------------

func (s *Server) handleAPIWhoami(w http.ResponseWriter, r *http.Request) {
	if !s.cfg().Auth.Enabled {
		writeJSON(w, http.StatusOK, apiWhoami{
			Name: "", Kind: "anonymous", AuthMode: "disabled",
			Hosts: s.cfg().VisibleHosts(config.Principal{}),
		})
		return
	}
	p := principalFromContext(r.Context())
	mode := "cookie"
	if p.Kind == config.PrincipalAgent {
		mode = "bearer"
	}
	writeJSON(w, http.StatusOK, apiWhoami{
		Name: p.Name, Kind: string(p.Kind), Groups: p.Groups,
		Hosts: s.cfg().VisibleHosts(p), AuthMode: mode,
	})
}

func (s *Server) handleAPIHostList(w http.ResponseWriter, r *http.Request) {
	hostsOut := make([]apiHost, 0, len(s.cfg().Hosts))
	for i := range s.cfg().Hosts {
		h := &s.cfg().Hosts[i]
		if !s.canDo(r, h.Name, config.ActionStatus) {
			continue
		}
		st, _ := s.registry.Get(h.Name)
		hostsOut = append(hostsOut, s.toAPIHost(r, h, st))
	}
	writeJSON(w, http.StatusOK, apiHostList{Hosts: hostsOut})
}

func (s *Server) handleAPIHost(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	h := s.cfg().HostByName(name)
	if h == nil || !s.canDo(r, name, config.ActionStatus) {
		writeAPIError(w, http.StatusNotFound, "host_not_found",
			"no such host, or no permission to see it")
		return
	}
	st, _ := s.registry.Get(name)
	writeJSON(w, http.StatusOK, s.toAPIHost(r, h, st))
}

// --- view-model conversion --------------------------------------------------

func (s *Server) toAPIHost(r *http.Request, h *config.Host, st hosts.Status) apiHost {
	return apiHost{
		Name:        h.Name,
		DisplayName: h.DisplayName,
		Hostname:    h.Hostname,
		MAC:         h.MAC,
		Broadcast:   h.Broadcast,
		Status:      toAPIStatus(st),
		Permissions: apiPermissions{
			CanStatus:   s.canDo(r, h.Name, config.ActionStatus),
			CanWake:     s.canDo(r, h.Name, config.ActionWake),
			CanShutdown: s.canDo(r, h.Name, config.ActionShutdown),
		},
		Checks: toAPIChecks(h.Checks),
	}
}

func toAPIStatus(st hosts.Status) apiStatus {
	out := apiStatus{Reachable: st.Reachable.String(), LastError: st.LastErr}
	if !st.LastChecked.IsZero() {
		t := st.LastChecked
		out.LastChecked = &t
	}
	if !st.LastChange.IsZero() {
		t := st.LastChange
		out.LastChange = &t
	}
	if st.Uptime > 0 {
		secs := int64(st.Uptime.Seconds())
		out.UptimeSec = &secs
	}
	if st.Load != (hosts.LoadInfo{}) {
		out.Load = &apiLoad{One: st.Load.One, Five: st.Load.Five, Fifteen: st.Load.Fifteen}
	}
	if st.Memory.TotalKB > 0 {
		used := max(st.Memory.TotalKB-st.Memory.AvailableKB, 0)
		pct := 0
		if st.Memory.TotalKB > 0 {
			pct = (used * 100) / st.Memory.TotalKB
		}
		out.Memory = &apiMemory{
			TotalKB: st.Memory.TotalKB, AvailableKB: st.Memory.AvailableKB, UsedPct: pct,
		}
	}
	for _, d := range st.Disks {
		out.Disks = append(out.Disks, apiDisk{Mount: d.Mount, FSType: d.FSType, UsedPct: d.UsedPct})
	}
	return out
}

func toAPIChecks(in map[string]config.Check) []apiCheckConfig {
	// Stable order: ping, uptime, load, memory, disk.
	order := []string{config.CheckPing, config.CheckUptime, config.CheckLoad, config.CheckMemory, config.CheckDisk}
	out := make([]apiCheckConfig, 0, len(in))
	for _, name := range order {
		c, ok := in[name]
		if !ok {
			continue
		}
		every := max(c.Every, 1)
		out = append(out, apiCheckConfig{Name: name, Enabled: c.Enabled, Every: every})
	}
	return out
}
