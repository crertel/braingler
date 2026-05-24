package sshca

import (
	"fmt"
	"strings"
)

// SetupSnippets renders the one-time configuration each homelab host needs
// to trust this user CA (and optionally this host CA). Returns a slice of
// (label, body) pairs intended for both CLI printout and the web bootstrap
// page.
//
// Two flavors are produced: a generic sshd_config drop-in and a NixOS module
// that achieves the same end state via services.openssh + environment.etc.
//
// hostCA may be nil when no host CA is configured.
func SetupSnippets(userCA, hostCA *CA, maintenanceUser string) []Snippet {
	out := []Snippet{
		{
			Label:    "User CA public key",
			Filename: "braingler_user_ca.pub",
			Body:     userCA.AuthorizedKey("braingler-user-ca") + "\n",
		},
		{
			Label: "sshd_config (any Linux): trust the user CA + run a maintenance user",
			Body: genericSSHDConfig(hostCA != nil),
		},
		{
			Label:    "NixOS module — drop into /etc/nixos/braingler-ssh.nix",
			Filename: "braingler-ssh.nix",
			Body:     nixosModule(userCA, hostCA, maintenanceUser),
		},
	}
	if hostCA != nil {
		out = append(out, Snippet{
			Label: "Host CA public key (clients add to ~/.ssh/known_hosts as @cert-authority)",
			Body:  hostCA.AuthorizedKey("braingler-host-ca") + "\n",
		})
		out = append(out, Snippet{
			Label: "Per-host (one-time): sign the host key with the host CA",
			Body: hostKeySigningInstructions(),
		})
	}
	return out
}

// Snippet is one labeled chunk of text the user is meant to copy somewhere.
type Snippet struct {
	Label    string
	Filename string // optional; suggested filename if downloading
	Body     string
}

func genericSSHDConfig(withHostCert bool) string {
	var b strings.Builder
	b.WriteString("# /etc/ssh/sshd_config (add these lines, then restart sshd)\n")
	b.WriteString("TrustedUserCAKeys /etc/ssh/braingler_user_ca.pub\n")
	if withHostCert {
		b.WriteString("HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\n")
	}
	b.WriteString("\n# Maintenance user — adjust to taste\n")
	b.WriteString("# (create the account separately, then in /etc/sudoers.d/braingler:)\n")
	b.WriteString("# braingler-maint ALL=(ALL) NOPASSWD: /sbin/shutdown -hP now\n")
	return b.String()
}

func nixosModule(userCA, hostCA *CA, maintenanceUser string) string {
	if maintenanceUser == "" {
		maintenanceUser = "braingler-maint"
	}
	userCAAuth := userCA.AuthorizedKey("braingler-user-ca")

	var extraConfig strings.Builder
	extraConfig.WriteString("TrustedUserCAKeys /etc/ssh/braingler_user_ca.pub\n")
	if hostCA != nil {
		extraConfig.WriteString("HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub\n")
	}

	return fmt.Sprintf(`# braingler-ssh.nix — import from configuration.nix
{ config, pkgs, ... }:

let
  brainglerMaint = "%s";
in {
  environment.etc."ssh/braingler_user_ca.pub".text = ''
    %s
  '';

  services.openssh = {
    enable = true;
    extraConfig = ''
%s    '';
  };

  users.users.${brainglerMaint} = {
    isNormalUser = true;
    description = "braingler maintenance user — receives short-lived signed certs";
    # No authorizedKeys here on purpose: login is via cert, not key.
  };

  security.sudo.extraRules = [{
    users = [ brainglerMaint ];
    commands = [
      { command = "${pkgs.systemd}/bin/shutdown -hP now"; options = [ "NOPASSWD" ]; }
    ];
  }];
}
`, maintenanceUser, userCAAuth, indent(extraConfig.String(), "      "))
}

func hostKeySigningInstructions() string {
	return `# Run on the braingler box once per host:
#   ssh root@HOST cat /etc/ssh/ssh_host_ed25519_key.pub > /tmp/HOST.pub
#   braingler sign-host-key HOST < /tmp/HOST.pub > /tmp/HOST-cert.pub
#   scp /tmp/HOST-cert.pub root@HOST:/etc/ssh/ssh_host_ed25519_key-cert.pub
#   ssh root@HOST systemctl reload sshd
`
}

func indent(s, prefix string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		if l == "" {
			continue
		}
		lines[i] = prefix + l
	}
	return strings.Join(lines, "\n") + "\n"
}
