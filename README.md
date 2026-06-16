# braingler

A Wake-on-LAN dashboard for a homelab fleet — and, increasingly, the fleet's
SSH certificate authority. braingler polls a set of hosts, shows their status,
wakes/shuts them down, and can mint short-lived SSH certificates (for humans at
the CLI/web UI and for agents over a JSON API).

## Build & run

It's a single Go binary. With Nix:

```bash
nix develop            # dev shell with go, gopls, linters
go build -o braingler .

# or build the package directly
nix build              # → ./result/bin/braingler
```

Run the server:

```bash
braingler serve --config config.json
```

See `config.example.json` for a fully-commented starting point; copy it to
`config.json` and edit. `braingler check --config config.json` validates a
config without starting anything.

## Commands

```
braingler serve         [--config PATH]                  Run the monitor + HTTP server.
braingler check         [--config PATH]                  Load and validate the config file.
braingler wake          [--config PATH] HOST             Send a Wake-on-LAN packet to HOST.
braingler shutdown      [--config PATH] HOST             Shut HOST down via SSH.
braingler hash-password                                  Read a password from stdin, print bcrypt hash.
braingler issue-token   --name NAME --groups G1,G2       Mint a new API bearer token.
braingler ca-info       [--config PATH]                  Print CA pubkeys + sshd_config / NixOS setup.
braingler sign-host-key [--config PATH] HOST < HOSTKEY   Sign a host's pubkey, write cert to stdout.
braingler sign-user-key [--config PATH] --principal P [--ttl 1h] [--gen] < USERKEY
                                                         Sign a user pubkey (or --gen one), write cert to stdout.
braingler version
```

## Protecting a host from wake / shutdown

A host entry can opt out of being woken or shut down through braingler, as a
safety pin (e.g. an always-on server you never want a stray dashboard click or
API call to power off):

```json
{ "name": "fileserver", "hostname": "...", "mac": "...", "broadcast": "...",
  "no_shutdown": true }
```

`no_shutdown` forbids the shutdown action and `no_wake` forbids wake — for
*every* caller, in the web UI, the API, and the CLI, regardless of auth (they
can only deny, never grant). A pinned host's wake/shutdown buttons disappear,
the API returns `403 action_forbidden`, and `braingler wake|shutdown` refuses.
Status/monitoring are unaffected.

## SSH certificate authority

braingler can act as an SSH CA with two independent roles, each a single
Ed25519 keypair (SSH has no notion of intermediate/chained CAs — the CA key
*is* the trust root, listed directly in `TrustedUserCAKeys` / as an
`@cert-authority` line):

- **User CA** — signs user certificates. Hosts trust it via `TrustedUserCAKeys`
  in `sshd_config`; the cert's principals become valid login names.
- **Host CA** (optional) — signs host certificates. Clients trust it via an
  `@cert-authority` line in `known_hosts`; this kills TOFU prompts and
  host-key-changed warnings after a re-image. When `host_ca_key_file` is set,
  braingler can *also* verify host certs on its own outbound SSH (monitoring /
  shutdown) — but only for hosts that opt in with `"verify_host_cert": true`.
  This is per-host on purpose: requiring certs globally would drop any host that
  hasn't been issued one. Unset hosts keep the default (no host verification).

Enable it in config:

```json
"ssh_ca": {
  "enabled": true,
  "key_file": "~/.local/state/braingler/ssh_ca",
  "host_ca_key_file": "~/.local/state/braingler/ssh_host_ca",
  "human_ttl_seconds": 86400,
  "agent_ttl_seconds": 300
}
```

### Providing vs. auto-generating the CA key

`key_file` (and `host_ca_key_file`) are loaded with provide-or-generate
semantics: if the file exists braingler **adopts** it, and if it's missing
braingler **generates** an Ed25519 key there (mode 0600) on first load.

Pre-placing the key is usually the better choice for a fleet: the CA *public*
key is then a known value *before* braingler ever runs, so you can commit it
into your hosts' trust config (e.g. a NixOS module) without first booting
braingler and reading the key back out of its state directory.

```bash
ssh-keygen -t ed25519 -f lab_user_ca -C "lab-user-ca"   # pre-place; point key_file at lab_user_ca
```

### Minting user certs — `sign-user-key`

This is the quick, fully **offline** path: it only needs read access to the CA
key file — no running server, no auth, no host entry in the config. The pubkey
to sign comes from stdin (or `--gen` makes a fresh keypair for you).

```bash
# You already have a key — feed the .pub, get a cert next to it:
braingler sign-user-key --config config.json --principal alice --ttl 1h \
  < ~/.ssh/id_ed25519.pub > ~/.ssh/id_ed25519-cert.pub

# No key yet — generate the keypair + cert as a labeled bundle:
braingler sign-user-key --config config.json --principal alice --gen

# Multiple logins, and a cert pinned to one command:
braingler sign-user-key --config config.json --principal alice,root \
  --force-command "uptime" --ttl 10m < key.pub
```

Flags:

| Flag | Meaning |
|------|---------|
| `--principal P[,P2,…]` | login name(s) the cert is valid for (required) |
| `--ttl 1h` | lifetime as a Go duration; default = `ssh_ca.human_ttl_seconds` |
| `--force-command CMD` | pin the cert to a single command (`force-command` critical option) |
| `--key-id ID` | override the cert KeyID (the audit string in sshd logs) |
| `--gen` | generate an ephemeral keypair instead of reading a pubkey from stdin |

Without `--gen`, the certificate is the *only* thing written to stdout (so
`> …-cert.pub` works); diagnostics go to stderr. With `--gen`, braingler holds
the only copy of the private key, so it prints a labeled bundle (private key,
public key, certificate) instead of a single pipeable line.

Verify any minted cert with `ssh-keygen -L -f …-cert.pub`.

### Minting host certs — `sign-host-key`

Requires `host_ca_key_file` to be set. Feed the host's public key on stdin:

```bash
ssh root@HOST cat /etc/ssh/ssh_host_ed25519_key.pub \
  | braingler sign-host-key --config config.json HOST > HOST-cert.pub
# then install HOST-cert.pub as /etc/ssh/ssh_host_ed25519_key-cert.pub and reload sshd
```

### Setting up fleet trust — `ca-info`

`braingler ca-info` prints the CA public keys plus ready-to-paste setup: a
generic `sshd_config` drop-in, a reusable NixOS module
(`services.braingler-ssh.*`), and a per-host usage example.

### Minting over the API (for agents)

When the server is running, `POST /api/v1/hosts/{name}/ssh-cert` (bearer-token
auth) mints a short-lived user cert scoped to one action on one host, bound via
`force-command` and clamped to `agent_ttl_seconds`. An empty request body also
makes braingler generate an ephemeral keypair for the caller. There's also a
human web form at `/ssh-cert`.
