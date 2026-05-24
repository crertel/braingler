package server

import (
	"net/http"

	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/sshca"
)

// ssh_setupView is the template payload for /ssh-setup.
type sshSetupView struct {
	Enabled           bool
	UserCAFingerprint string
	HostCAFingerprint string // empty when no host CA is configured
	Snippets          []sshca.Snippet
	Hosts             []*config.Host
	ConfigPath        string
	ShowSSHCert       bool // sibling-page nav: show "SSH cert" link when permitted
}

// handleSSHSetup renders the maintainer bootstrap page: CA fingerprints,
// sshd_config + NixOS snippets, and a per-host signing checklist. Visible to
// principals with the ca-bootstrap action on any host.
func (s *Server) handleSSHSetup(w http.ResponseWriter, r *http.Request) {
	v := sshSetupView{
		Enabled:    s.userCA != nil,
		ConfigPath: "config.json", // displayed verbatim in copyable command; user can edit
	}
	if !v.Enabled {
		s.render(w, "ssh_setup.html", v)
		return
	}

	v.UserCAFingerprint = s.userCA.Fingerprint()
	maintUser := s.cfg().SSHDefaults.User
	if maintUser == "" {
		maintUser = "braingler-maint"
	}
	v.Snippets = sshca.SetupSnippets(s.userCA, s.hostCA, maintUser)
	if s.hostCA != nil {
		v.HostCAFingerprint = s.hostCA.Fingerprint()
	}

	// Hosts the principal has ca-bootstrap access to — the checklist only
	// shows what they're permitted to act on. Side-effect: also note whether
	// they have ssh-cert anywhere, for the sibling-page nav link.
	for i := range s.cfg().Hosts {
		name := s.cfg().Hosts[i].Name
		if s.canDo(r, name, config.ActionCABootstrap) {
			v.Hosts = append(v.Hosts, &s.cfg().Hosts[i])
		}
		v.ShowSSHCert = v.ShowSSHCert || s.canDo(r, name, config.ActionSSHCert)
	}
	s.render(w, "ssh_setup.html", v)
}
