package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"io"

	"github.com/crertel/braingler/internal/auth"
	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/events"
	"github.com/crertel/braingler/internal/hosts"
	"github.com/crertel/braingler/internal/monitor"
	"github.com/crertel/braingler/internal/server"
	"github.com/crertel/braingler/internal/sshca"
	"github.com/crertel/braingler/internal/sshx"
	"github.com/crertel/braingler/internal/wol"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const usage = `braingler — Wake-on-LAN dashboard for homelab hosts

Usage:
  braingler serve         [--config PATH]                  Run the monitor + HTTP server.
  braingler check         [--config PATH]                  Load and validate the config file.
  braingler wake          [--config PATH] HOST             Send a Wake-on-LAN packet to HOST.
  braingler shutdown      [--config PATH] HOST             Shut HOST down via SSH.
  braingler hash-password                                  Read a password from stdin, print bcrypt hash.
  braingler issue-token   --name NAME --groups G1,G2       Mint a new API bearer token.
  braingler ca-info       [--config PATH]                  Print CA pubkeys + sshd_config / NixOS setup.
  braingler sign-host-key [--config PATH] HOST < HOSTKEY   Sign a host's pubkey, write cert to stdout.
  braingler version
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}

	switch os.Args[1] {
	case "version":
		fmt.Println("braingler 0.0.1")
	case "check":
		os.Exit(runCheck(os.Args[2:]))
	case "hash-password":
		os.Exit(runHashPassword())
	case "serve":
		os.Exit(runServe(os.Args[2:]))
	case "wake":
		os.Exit(runWake(os.Args[2:]))
	case "shutdown":
		os.Exit(runShutdown(os.Args[2:]))
	case "issue-token":
		os.Exit(runIssueToken(os.Args[2:]))
	case "ca-info":
		os.Exit(runCAInfo(os.Args[2:]))
	case "sign-host-key":
		os.Exit(runSignHostKey(os.Args[2:]))
	case "-h", "--help", "help":
		fmt.Print(usage)
	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n%s", os.Args[1], usage)
		os.Exit(2)
	}
}

func runServe(args []string) int {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	path := fs.String("config", "config.json", "path to config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := config.Load(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return 1
	}
	cfgPtr := config.NewPointer(c)

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reg := hosts.New()
	evlog := events.New(1024)

	var userCA, hostCA *sshca.CA
	if c.SSHCA.Enabled {
		userCA, err = sshca.Load(c.SSHCA.KeyFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "ssh_ca: %v\n", err)
			return 1
		}
		logger.Info("loaded user CA", "fingerprint", userCA.Fingerprint())
		if c.SSHCA.HostCAKeyFile != "" {
			hostCA, err = sshca.Load(c.SSHCA.HostCAKeyFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "ssh_ca host: %v\n", err)
				return 1
			}
			logger.Info("loaded host CA", "fingerprint", hostCA.Fingerprint())
		}
	}
	sshMgr, err := sshx.NewManager(cfgPtr, userCA, hostCA)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sshx: %v\n", err)
		return 1
	}

	mon := monitor.New(cfgPtr, reg, logger, sshMgr).WithEventLog(evlog)

	var authn *auth.Authenticator
	if c.Auth.Enabled {
		authn, err = auth.New(cfgPtr, auth.DefaultKeyPath())
		if err != nil {
			fmt.Fprintf(os.Stderr, "auth init: %v\n", err)
			return 1
		}
	}

	wake := func(_ context.Context, h *config.Host) error {
		mac, _ := net.ParseMAC(h.MAC)
		bcast := net.ParseIP(h.Broadcast)
		return wol.Wake(mac, bcast)
	}
	shutdown := func(ctx context.Context, h *config.Host, _ config.SSHConfig) error {
		return sshMgr.Shutdown(ctx, h)
	}

	srv, err := server.New(cfgPtr, reg, logger, authn, evlog, userCA, hostCA, wake, shutdown)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server init: %v\n", err)
		return 1
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	logger.Info("braingler starting", "hosts", len(c.Hosts), "poll_s", c.PollIntervalSeconds)

	var wg sync.WaitGroup
	wg.Go(func() { mon.Run(ctx) })
	wg.Go(func() {
		if err := srv.ListenAndServe(ctx); err != nil {
			logger.Error("http server stopped", "err", err)
			cancel() // bring the monitor down too if the server dies
		}
	})
	wg.Wait()
	logger.Info("braingler stopped")
	return 0
}

// loadConfigFromArgs parses --config from args and returns the loaded config
// plus the remaining positional args. On error it prints and returns nil.
func loadConfigFromArgs(name string, args []string) (*config.Config, []string, int) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	path := fs.String("config", "config.json", "path to config file")
	if err := fs.Parse(args); err != nil {
		return nil, nil, 2
	}
	c, err := config.Load(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return nil, nil, 1
	}
	return c, fs.Args(), 0
}

func runWake(args []string) int {
	c, rest, code := loadConfigFromArgs("wake", args)
	if c == nil {
		return code
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "wake: expected exactly one HOST argument")
		return 2
	}
	h := c.HostByName(rest[0])
	if h == nil {
		fmt.Fprintf(os.Stderr, "wake: unknown host %q\n", rest[0])
		return 1
	}
	mac, _ := net.ParseMAC(h.MAC)
	bcast := net.ParseIP(h.Broadcast)
	if err := wol.Wake(mac, bcast); err != nil {
		fmt.Fprintf(os.Stderr, "wake: %v\n", err)
		return 1
	}
	fmt.Printf("sent magic packet for %s (%s -> %s)\n", h.Name, h.MAC, h.Broadcast)
	return 0
}

func runShutdown(args []string) int {
	c, rest, code := loadConfigFromArgs("shutdown", args)
	if c == nil {
		return code
	}
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "shutdown: expected exactly one HOST argument")
		return 2
	}
	h := c.HostByName(rest[0])
	if h == nil {
		fmt.Fprintf(os.Stderr, "shutdown: unknown host %q\n", rest[0])
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := sshx.Shutdown(ctx, h.Hostname, c.EffectiveSSH(h)); err != nil {
		fmt.Fprintf(os.Stderr, "shutdown %s: %v\n", h.Name, err)
		return 1
	}
	fmt.Printf("shutdown requested on %s\n", h.Name)
	return 0
}

func runCheck(args []string) int {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	path := fs.String("config", "config.json", "path to config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	c, err := config.Load(*path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return 1
	}
	fmt.Printf("config OK: %d host(s), auth=%v\n", len(c.Hosts), c.Auth.Enabled)
	return 0
}

// loadCAs opens the user CA and (optionally) the host CA from a config. If
// host_ca_key_file is unset, returns userCA, nil. Caller-supplied error
// strings are printed by the subcommand.
func loadCAs(c *config.Config) (user *sshca.CA, host *sshca.CA, err error) {
	if !c.SSHCA.Enabled {
		return nil, nil, errors.New("ssh_ca.enabled is false in config")
	}
	user, err = sshca.Load(c.SSHCA.KeyFile)
	if err != nil {
		return nil, nil, err
	}
	if c.SSHCA.HostCAKeyFile != "" {
		host, err = sshca.Load(c.SSHCA.HostCAKeyFile)
		if err != nil {
			return nil, nil, err
		}
	}
	return user, host, nil
}

func runCAInfo(args []string) int {
	c, _, code := loadConfigFromArgs("ca-info", args)
	if c == nil {
		return code
	}
	user, host, err := loadCAs(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ca-info: %v\n", err)
		return 1
	}
	fmt.Printf("User CA: %s\n", user.Fingerprint())
	if host != nil {
		fmt.Printf("Host CA: %s\n", host.Fingerprint())
	} else {
		fmt.Println("Host CA: (none configured — set ssh_ca.host_ca_key_file to enable)")
	}
	fmt.Println()

	maintUser := c.SSHDefaults.User
	if maintUser == "" {
		maintUser = "braingler-maint"
	}
	for _, s := range sshca.SetupSnippets(user, host, maintUser) {
		fmt.Println("---", s.Label, "---")
		fmt.Println()
		fmt.Println(s.Body)
	}
	return 0
}

func runSignHostKey(args []string) int {
	fs := flag.NewFlagSet("sign-host-key", flag.ContinueOnError)
	cfgPath := fs.String("config", "config.json", "path to config file")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) != 1 {
		fmt.Fprintln(os.Stderr, "sign-host-key: expected exactly one HOST argument")
		return 2
	}
	hostName := rest[0]

	c, err := config.Load(*cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "config invalid: %v\n", err)
		return 1
	}
	_, hostCA, err := loadCAs(c)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign-host-key: %v\n", err)
		return 1
	}
	if hostCA == nil {
		fmt.Fprintln(os.Stderr, "sign-host-key: ssh_ca.host_ca_key_file is not set")
		return 1
	}

	pubBytes, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign-host-key: read stdin: %v\n", err)
		return 1
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign-host-key: parse pubkey: %v\n", err)
		return 1
	}

	principals := []string{hostName}
	if h := c.HostByName(hostName); h != nil && h.Hostname != "" && h.Hostname != hostName {
		principals = append(principals, h.Hostname)
	}
	cert, err := hostCA.SignHostCert(pub, sshca.HostCertOptions{
		KeyID:           hostName,
		ValidPrincipals: principals,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sign-host-key: %v\n", err)
		return 1
	}
	fmt.Println(sshca.MarshalCertificate(cert, "host="+hostName))
	return 0
}

func runIssueToken(args []string) int {
	fs := flag.NewFlagSet("issue-token", flag.ContinueOnError)
	name := fs.String("name", "", "human-readable name for the token")
	groupsCSV := fs.String("groups", "", "comma-separated group names")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *name == "" || *groupsCSV == "" {
		fmt.Fprintln(os.Stderr, "issue-token: --name and --groups are required")
		return 2
	}
	groups := make([]string, 0)
	for g := range strings.SplitSeq(*groupsCSV, ",") {
		if g = strings.TrimSpace(g); g != "" {
			groups = append(groups, g)
		}
	}
	if len(groups) == 0 {
		fmt.Fprintln(os.Stderr, "issue-token: --groups must list at least one group")
		return 2
	}

	tok, hash, err := auth.MintToken()
	if err != nil {
		fmt.Fprintf(os.Stderr, "issue-token: %v\n", err)
		return 1
	}

	entry := config.APIToken{Name: *name, TokenHash: hash, Groups: groups}
	pretty, _ := json.MarshalIndent(entry, "  ", "  ")

	fmt.Println("New API token — this is the only time it will be shown:")
	fmt.Println()
	fmt.Println("  " + tok)
	fmt.Println()
	fmt.Println("Add this entry to your config's auth.api_tokens array:")
	fmt.Println()
	fmt.Println("  " + string(pretty))
	fmt.Println()
	fmt.Println("Send it in API requests as:  Authorization: Bearer " + tok)
	return 0
}

func runHashPassword() int {
	pw1, err := readPassword("Password: ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	pw2, err := readPassword("Confirm:  ")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if string(pw1) != string(pw2) {
		fmt.Fprintln(os.Stderr, "passwords do not match")
		return 1
	}
	if len(pw1) == 0 {
		fmt.Fprintln(os.Stderr, "empty password")
		return 1
	}
	hash, err := bcrypt.GenerateFromPassword(pw1, bcrypt.DefaultCost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "hash failed: %v\n", err)
		return 1
	}
	fmt.Println(string(hash))
	return 0
}

func readPassword(prompt string) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return nil, errors.New("stdin is not a terminal; refusing to read password")
	}
	fmt.Fprint(os.Stderr, prompt)
	b, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	return b, err
}
