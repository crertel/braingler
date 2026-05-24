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
// Three flavors are produced:
//
//   - A generic sshd_config drop-in for any Linux host.
//   - A reusable NixOS module (parameterized via services.braingler-ssh.*).
//   - A per-host import example showing how to wire the module in.
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
			Body:  genericSSHDConfig(hostCA != nil),
		},
		{
			Label:    "NixOS: reusable module — drop into /etc/nixos/braingler-ssh.nix once",
			Filename: "braingler-ssh.nix",
			Body:     nixosModule(),
		},
		{
			Label: "NixOS: per-host usage — drop into configuration.nix",
			Body:  nixosUsageExample(userCA, hostCA, maintenanceUser),
		},
	}
	if hostCA != nil {
		out = append(out, Snippet{
			Label: "Host CA public key (clients add to ~/.ssh/known_hosts as @cert-authority)",
			Body:  hostCA.AuthorizedKey("braingler-host-ca") + "\n",
		})
		out = append(out, Snippet{
			Label: "Per-host (one-time): sign the host key with the host CA",
			Body:  hostKeySigningInstructions(),
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

// nixosModule renders a reusable NixOS module file. The body is static — no
// per-host substitution — so the same file works for every host in the
// fleet; per-host details land in the configuration.nix import (see
// nixosUsageExample).
func nixosModule() string {
	return `# braingler-ssh.nix — reusable NixOS module.
# Set services.braingler-ssh.* on each host that needs it; see the usage
# example for the values to pass.
{ config, lib, pkgs, ... }:

let
  cfg = config.services.braingler-ssh;
in {
  options.services.braingler-ssh = {
    enable = lib.mkEnableOption "trust the braingler SSH user CA";

    userCAKey = lib.mkOption {
      type = lib.types.str;
      description = ''
        Public key of the braingler user CA in authorized_keys format
        (one line, starts with ssh-ed25519 AAAA...). Copy this from
        braingler's /ssh-setup page or "braingler ca-info".
      '';
    };

    hostCert = lib.mkOption {
      type = lib.types.nullOr lib.types.path;
      default = null;
      description = ''
        Path to this host's signed host cert produced by
        "braingler sign-host-key <name>". Leave null to skip host-cert
        presentation (sshd will offer its plain host key).
      '';
    };

    maintenanceUser = lib.mkOption {
      type = lib.types.str;
      default = "braingler-maint";
      description = "Local Unix user braingler logs in as for status checks and shutdown.";
    };

    allowShutdown = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = "Grant the maintenance user passwordless sudo for shutdown -hP now.";
    };
  };

  config = lib.mkIf cfg.enable {
    environment.etc."ssh/braingler_user_ca.pub".text = cfg.userCAKey + "\n";

    environment.etc."ssh/ssh_host_ed25519_key-cert.pub" = lib.mkIf (cfg.hostCert != null) {
      source = cfg.hostCert;
    };

    services.openssh = {
      enable = true;
      extraConfig = ''
        TrustedUserCAKeys /etc/ssh/braingler_user_ca.pub
      '' + lib.optionalString (cfg.hostCert != null) ''
        HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub
      '';
    };

    users.users.${cfg.maintenanceUser} = {
      isNormalUser = true;
      description = "braingler maintenance user — receives short-lived signed certs";
      # No authorizedKeys: login is via cert, not key.
    };

    security.sudo.extraRules = lib.mkIf cfg.allowShutdown [{
      users = [ cfg.maintenanceUser ];
      commands = [
        { command = "${pkgs.systemd}/bin/shutdown -hP now"; options = [ "NOPASSWD" ]; }
      ];
    }];
  };
}
`
}

// nixosUsageExample shows how a single host's configuration.nix imports the
// module and supplies its own user-CA pubkey (always the same) and host cert
// (per host, only when the host CA is in use).
func nixosUsageExample(userCA, hostCA *CA, maintenanceUser string) string {
	userCAAuth := userCA.AuthorizedKey("braingler-user-ca")
	if maintenanceUser == "" {
		maintenanceUser = "braingler-maint"
	}

	hostCertLine := "# hostCert = ./this-hosts-cert.pub;  # uncomment after running `braingler sign-host-key <name>`"
	if hostCA != nil {
		hostCertLine = "hostCert = ./this-hosts-cert.pub;  # produced by `braingler sign-host-key <name>`"
	}

	return fmt.Sprintf(`# configuration.nix (or per-host file)
{ ... }: {
  imports = [ ./braingler-ssh.nix ];

  services.braingler-ssh = {
    enable = true;
    userCAKey = "%s";
    %s
    maintenanceUser = "%s";
  };
}
`, userCAAuth, hostCertLine, maintenanceUser)
}

func hostKeySigningInstructions() string {
	return `# Two flavors of getting the signed cert onto each host:
#
# A) Generic Linux (scp + sshd reload):
#    ssh root@HOST cat /etc/ssh/ssh_host_ed25519_key.pub > /tmp/HOST.pub
#    braingler sign-host-key HOST < /tmp/HOST.pub > /tmp/HOST-cert.pub
#    scp /tmp/HOST-cert.pub root@HOST:/etc/ssh/ssh_host_ed25519_key-cert.pub
#    ssh root@HOST systemctl reload sshd
#
# B) NixOS-managed host (declarative via the braingler-ssh module):
#    ssh root@HOST cat /etc/ssh/ssh_host_ed25519_key.pub > HOST.pub
#    braingler sign-host-key HOST < HOST.pub > /etc/nixos/HOST-cert.pub
#    # In the host's configuration.nix, set:
#    #   services.braingler-ssh.hostCert = ./HOST-cert.pub;
#    nixos-rebuild switch --target-host root@HOST
`
}

// indent is unused now that the NixOS module body is fully static, but
// kept here since future additions may want it.
var _ = strings.Repeat // silence unused-import potential
