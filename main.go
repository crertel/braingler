package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/crertel/braingler/internal/auth"
	"github.com/crertel/braingler/internal/config"
	"github.com/crertel/braingler/internal/hosts"
	"github.com/crertel/braingler/internal/monitor"
	"github.com/crertel/braingler/internal/server"
	"github.com/crertel/braingler/internal/sshx"
	"github.com/crertel/braingler/internal/wol"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const usage = `braingler — Wake-on-LAN dashboard for homelab hosts

Usage:
  braingler serve    [--config PATH]            Run the monitor (HTTP server arrives later).
  braingler check    [--config PATH]            Load and validate the config file.
  braingler wake     [--config PATH] HOST       Send a Wake-on-LAN packet to HOST.
  braingler shutdown [--config PATH] HOST       Shut HOST down via SSH.
  braingler hash-password                       Read a password from stdin, print bcrypt hash.
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

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	reg := hosts.New()
	mon := monitor.New(c, reg, logger)

	var authn *auth.Authenticator
	if c.Auth.Enabled {
		var err error
		authn, err = auth.New(c, auth.DefaultKeyPath())
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
	shutdown := func(ctx context.Context, h *config.Host, sshCfg config.SSHConfig) error {
		return sshx.Shutdown(ctx, h.Hostname, sshCfg)
	}

	srv, err := server.New(c, reg, logger, authn, wake, shutdown)
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
