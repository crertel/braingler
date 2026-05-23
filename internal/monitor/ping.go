package monitor

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// pingTimeout is the wall-clock budget for one ping invocation. The `-W 1`
// flag bounds the per-packet wait; this is a belt-and-suspenders cap.
const pingTimeout = 2 * time.Second

// Ping reports whether hostname responds to ICMP.
//
//	reachable=true,  err=nil  : host replied
//	reachable=false, err=nil  : host did not reply (normal "down" case)
//	reachable=false, err!=nil : something stopped us from telling (missing
//	                             binary, permission denied, DNS, etc.)
func Ping(ctx context.Context, hostname string) (bool, error) {
	cctx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()

	var stderr bytes.Buffer
	cmd := exec.CommandContext(cctx, "ping", "-c", "1", "-W", "1", "-n", "-q", hostname)
	cmd.Stderr = &stderr

	switch err := cmd.Run().(type) {
	case nil:
		return true, nil
	case *exec.ExitError:
		// ping's exit code 1 means "no reply" — the host is just down.
		// Anything else (2 = other error) is a real problem worth surfacing.
		if err.ExitCode() == 1 {
			return false, nil
		}
		return false, fmt.Errorf("ping exit %d: %s", err.ExitCode(), strings.TrimSpace(stderr.String()))
	default:
		if errors.Is(cctx.Err(), context.DeadlineExceeded) {
			return false, nil
		}
		return false, err
	}
}
