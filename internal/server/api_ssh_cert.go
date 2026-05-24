package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/sshca"
	"golang.org/x/crypto/ssh"
)

// apiSSHCertRequest is the body of POST /api/v1/hosts/{name}/ssh-cert.
// All fields are optional; an empty body works (asks the server to mint an
// ephemeral keypair AND a cert for the shutdown action).
type apiSSHCertRequest struct {
	Action     string `json:"action,omitempty"`      // defaults to "shutdown"
	PublicKey  string `json:"public_key,omitempty"`  // if empty, server generates an ephemeral keypair
	TTLSeconds int    `json:"ttl_seconds,omitempty"` // clamped to ssh_ca.agent_ttl_seconds
}

// apiSSHCertResponse is what the agent receives. PrivateKey is populated
// only when the caller didn't supply a PublicKey.
type apiSSHCertResponse struct {
	Certificate    string    `json:"certificate"`
	PublicKey      string    `json:"public_key"`
	PrivateKey     string    `json:"private_key,omitempty"`
	Principal      string    `json:"principal"`
	ForceCommand   string    `json:"force_command"`
	ExpiresAt      time.Time `json:"expires_at"`
	ActionID       string    `json:"action_id"`
	CAFingerprint  string    `json:"ca_fingerprint"`
}

// handleAPISSHCert mints a short-lived user certificate authorizing the
// caller to perform one specific action on one host. Cert is bound to that
// action via force-command; reuse on other commands or hosts will fail at
// sshd.
func (s *Server) handleAPISSHCert(w http.ResponseWriter, r *http.Request) {
	if s.userCA == nil {
		writeAPIError(w, http.StatusServiceUnavailable, "ssh_ca_disabled",
			"ssh_ca is not enabled on this server")
		return
	}

	h, ok := s.requireAPIHostPerm(w, r, config.ActionSSHCert)
	if !ok {
		return
	}

	var req apiSSHCertRequest
	if err := decodeOptionalJSON(r.Body, &req); err != nil {
		writeAPIError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	if req.Action == "" {
		req.Action = config.ActionShutdown
	}

	cmd, err := commandForAction(req.Action)
	if err != nil {
		writeAPIError(w, http.StatusBadRequest, "unknown_action", err.Error())
		return
	}

	// The agent must also have the action they're asking to be authorized
	// for — ssh-cert lets you mint, but only for actions you already own.
	if !s.canDo(r, h.Name, req.Action) {
		writeAPIError(w, http.StatusForbidden, "action_forbidden",
			"not permitted to "+req.Action+" "+h.Name)
		return
	}

	ttl := time.Duration(clampTTL(req.TTLSeconds, s.cfg().SSHCA.AgentTTLSeconds)) * time.Second

	var pubKey ssh.PublicKey
	var ephemeralPrivPEM []byte
	if req.PublicKey != "" {
		parsed, _, _, _, err := ssh.ParseAuthorizedKey([]byte(req.PublicKey))
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "bad_public_key", err.Error())
			return
		}
		pubKey = parsed
	} else {
		ephemeralPrivPEM, pubKey, err = sshca.GenerateEphemeralUserKeypair()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "ephemeral_keygen_failed", err.Error())
			return
		}
	}

	actor := principalFromContext(r.Context()).Name
	actionID := newActionID()
	principal := s.cfg().MaintenanceUser(h)
	if principal == "" {
		writeAPIError(w, http.StatusInternalServerError, "no_maintenance_user",
			"no maintenance_user (set ssh_defaults.user or host.maintenance_user)")
		return
	}

	cert, err := s.userCA.SignUserCert(pubKey, sshca.UserCertOptions{
		KeyID: fmt.Sprintf("agent=%s action=%s action_id=%s host=%s",
			actor, req.Action, actionID, h.Name),
		ValidPrincipals:   []string{principal},
		TTL:               ttl,
		ForceCommand:      cmd,
		NoPTY:             true,
		NoPortForwarding:  true,
		NoX11Forwarding:   true,
		NoAgentForwarding: true,
	})
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, "sign_failed", err.Error())
		return
	}

	resp := apiSSHCertResponse{
		Certificate:   sshca.MarshalCertificate(cert, "agent="+actor),
		PublicKey:     string(ssh.MarshalAuthorizedKey(pubKey)),
		Principal:     principal,
		ForceCommand:  cmd,
		ExpiresAt:     time.Unix(int64(cert.ValidBefore), 0).UTC(),
		ActionID:      actionID,
		CAFingerprint: s.userCA.Fingerprint(),
	}
	if ephemeralPrivPEM != nil {
		resp.PrivateKey = string(ephemeralPrivPEM)
	}

	s.logger.Info("api ssh-cert minted",
		"host", h.Name, "action", req.Action, "action_id", actionID,
		"actor", actor, "principal", principal, "ttl_s", int(ttl.Seconds()))
	writeJSON(w, http.StatusOK, resp)
}

// commandForAction returns the sshd-side command that a cert for the named
// action is allowed to run. Today only shutdown exists; future actions (e.g.
// run-command, reboot) will plug in here.
func commandForAction(action string) (string, error) {
	switch action {
	case config.ActionShutdown:
		return "sudo -n shutdown -hP now", nil
	default:
		return "", fmt.Errorf("no SSH command maps to action %q (supported: %s)",
			action, config.ActionShutdown)
	}
}

// clampTTL returns requested if it's in (0, max], otherwise max. A requested
// 0 is treated as "use the default."
func clampTTL(requested, max int) int {
	if requested <= 0 || requested > max {
		return max
	}
	return requested
}

// decodeOptionalJSON parses JSON from r into v. An empty body (io.EOF) is
// treated as "no fields set" — handy for endpoints where every parameter
// has a sensible default.
func decodeOptionalJSON(r io.Reader, v any) error {
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
