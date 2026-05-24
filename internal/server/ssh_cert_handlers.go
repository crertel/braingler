package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// sshCertResult is what we hand the template after a successful sign.
type sshCertResult struct {
	HostName          string
	Principal         string
	Certificate       string
	SSHConfigSnippet  string
	ExpiresAt         string
	SuggestedFilename string
}

// sshCertView is the data the form/result template renders against. Either
// Result is set (post-success) OR Hosts/DefaultPrincipal are (pre-submit).
type sshCertView struct {
	Hosts            []string
	SelectedHost     string
	DefaultPrincipal string
	SubmittedKey     string
	Error            string
	Result           *sshCertResult
	ShowCABootstrap  bool // sibling-page nav: show "Host setup" link when permitted
}

// handleSSHCertGet renders the form. Hosts are filtered to those the caller
// has ssh-cert action on; if none, we still render the page so they see why.
func (s *Server) handleSSHCertGet(w http.ResponseWriter, r *http.Request) {
	if s.userCA == nil {
		s.render(w, "ssh_cert.html", sshCertView{Error: "SSH CA is not enabled on this server."})
		return
	}
	v := s.newSSHCertForm(r, "", "")
	s.render(w, "ssh_cert.html", v)
}

// handleSSHCertPost signs the submitted pubkey and renders the result page.
// Validation errors fall through to a re-rendered form with the error band.
func (s *Server) handleSSHCertPost(w http.ResponseWriter, r *http.Request) {
	if s.userCA == nil {
		s.render(w, "ssh_cert.html", sshCertView{Error: "SSH CA is not enabled on this server."})
		return
	}
	if err := r.ParseForm(); err != nil {
		s.render(w, "ssh_cert.html", s.newSSHCertForm(r, "", "bad form: "+err.Error()))
		return
	}
	host := strings.TrimSpace(r.PostForm.Get("host"))
	principal := strings.TrimSpace(r.PostForm.Get("principal"))
	pubText := strings.TrimSpace(r.PostForm.Get("public_key"))

	if host == "" || principal == "" || pubText == "" {
		s.render(w, "ssh_cert.html", s.newSSHCertForm(r, pubText, "host, principal, and public key are all required"))
		return
	}
	h := s.cfg().HostByName(host)
	if h == nil || !s.canDo(r, host, config.ActionSSHCert) {
		s.render(w, "ssh_cert.html", s.newSSHCertForm(r, pubText, "no such host, or you don't have ssh-cert access to it"))
		return
	}
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(pubText))
	if err != nil {
		s.render(w, "ssh_cert.html", s.newSSHCertForm(r, pubText, "could not parse public key: "+err.Error()))
		return
	}

	ttl := time.Duration(s.cfg().SSHCA.HumanTTLSeconds) * time.Second
	actor := principalFromContext(r.Context()).Name
	cert, err := s.userCA.SignUserCert(pubKey, sshca.UserCertOptions{
		KeyID:           fmt.Sprintf("human=%s host=%s", actor, h.Name),
		ValidPrincipals: []string{principal},
		TTL:             ttl,
		// No force-command — humans need a shell.
	})
	if err != nil {
		s.render(w, "ssh_cert.html", s.newSSHCertForm(r, pubText, "sign failed: "+err.Error()))
		return
	}

	result := &sshCertResult{
		HostName:          h.Name,
		Principal:         principal,
		Certificate:       sshca.MarshalCertificate(cert, "human="+actor),
		ExpiresAt:         time.Unix(int64(cert.ValidBefore), 0).UTC().Format(time.RFC1123),
		SuggestedFilename: fmt.Sprintf("braingler-%s-cert.pub", h.Name),
	}
	result.SSHConfigSnippet = fmt.Sprintf(`Host %s
  HostName %s
  User %s
  CertificateFile ~/.ssh/%s
`, h.Name, h.Hostname, principal, result.SuggestedFilename)

	s.logger.Info("human ssh-cert minted",
		"host", h.Name, "principal", principal, "actor", actor, "ttl_s", int(ttl.Seconds()))
	// Reuse the form builder just to recompute nav flags for the success page.
	v := s.newSSHCertForm(r, "", "")
	v.Result = result
	s.render(w, "ssh_cert.html", v)
}

// newSSHCertForm builds the form-state view: hosts the caller can sign for,
// a default principal (the caller's own username), and an optional error.
func (s *Server) newSSHCertForm(r *http.Request, submittedKey, errMsg string) sshCertView {
	p := principalFromContext(r.Context())
	hosts := make([]string, 0, len(s.cfg().Hosts))
	canCABootstrap := false
	for i := range s.cfg().Hosts {
		name := s.cfg().Hosts[i].Name
		if s.canDo(r, name, config.ActionSSHCert) {
			hosts = append(hosts, name)
		}
		canCABootstrap = canCABootstrap || s.canDo(r, name, config.ActionCABootstrap)
	}
	def := p.Name
	if def == "" {
		def = "root"
	}
	return sshCertView{
		Hosts:            hosts,
		DefaultPrincipal: def,
		SubmittedKey:     submittedKey,
		Error:            errMsg,
		ShowCABootstrap:  canCABootstrap,
	}
}
