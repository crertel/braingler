package monitor

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/crertel/braingler/internal/hosts"
)

// realFSTypes is the set of filesystem types we consider "real disks" worth
// reporting. Everything else (tmpfs, devtmpfs, overlay, cgroup, …) is noise
// in a status dashboard.
var realFSTypes = map[string]bool{
	"ext2": true, "ext3": true, "ext4": true,
	"btrfs": true, "xfs": true, "zfs": true,
	"f2fs": true, "jfs": true,
	"vfat": true, "ntfs": true, "ntfs-3g": true, "exfat": true,
}

// parseUptime reads `/proc/uptime`, whose first whitespace-separated field is
// seconds-since-boot as a float.
func parseUptime(s string) (time.Duration, error) {
	fields := strings.Fields(s)
	if len(fields) < 1 {
		return 0, fmt.Errorf("uptime: empty output")
	}
	secs, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return 0, fmt.Errorf("uptime: parse %q: %w", fields[0], err)
	}
	return time.Duration(secs * float64(time.Second)), nil
}

// parseLoad reads `/proc/loadavg`, of the form "0.10 0.20 0.30 1/200 12345".
func parseLoad(s string) (hosts.LoadInfo, error) {
	fields := strings.Fields(s)
	if len(fields) < 3 {
		return hosts.LoadInfo{}, fmt.Errorf("loadavg: need 3+ fields, got %d", len(fields))
	}
	parse := func(f string) (float64, error) {
		v, err := strconv.ParseFloat(f, 64)
		if err != nil {
			return 0, fmt.Errorf("loadavg: parse %q: %w", f, err)
		}
		return v, nil
	}
	one, err := parse(fields[0])
	if err != nil {
		return hosts.LoadInfo{}, err
	}
	five, err := parse(fields[1])
	if err != nil {
		return hosts.LoadInfo{}, err
	}
	fifteen, err := parse(fields[2])
	if err != nil {
		return hosts.LoadInfo{}, err
	}
	return hosts.LoadInfo{One: one, Five: five, Fifteen: fifteen}, nil
}

// parseMemInfo extracts MemTotal and MemAvailable (in kB) from /proc/meminfo.
//
// /proc/meminfo lines look like:
//
//	MemTotal:       16384000 kB
//	MemAvailable:   12345678 kB
func parseMemInfo(s string) (hosts.MemInfo, error) {
	var m hosts.MemInfo
	var sawTotal, sawAvail bool
	for line := range strings.SplitSeq(s, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.TrimSuffix(fields[0], ":")
		val, err := strconv.Atoi(fields[1])
		if err != nil {
			continue
		}
		switch key {
		case "MemTotal":
			m.TotalKB = val
			sawTotal = true
		case "MemAvailable":
			m.AvailableKB = val
			sawAvail = true
		}
		if sawTotal && sawAvail {
			break
		}
	}
	if !sawTotal {
		return hosts.MemInfo{}, fmt.Errorf("meminfo: MemTotal not found")
	}
	if !sawAvail {
		// MemAvailable was added in kernel 3.14 (2014). If a host is old
		// enough to lack it, fall back to MemFree so we at least show
		// *something* — call it Available since that's how the UI labels it.
		for line := range strings.SplitSeq(s, "\n") {
			fields := strings.Fields(line)
			if len(fields) >= 2 && strings.TrimSuffix(fields[0], ":") == "MemFree" {
				if v, err := strconv.Atoi(fields[1]); err == nil {
					m.AvailableKB = v
					sawAvail = true
				}
				break
			}
		}
	}
	if !sawAvail {
		return hosts.MemInfo{}, fmt.Errorf("meminfo: MemAvailable and MemFree both missing")
	}
	return m, nil
}

// parseDfOutput parses `df --output=target,fstype,pcent`, which prints a
// header line followed by one row per mount:
//
//	Mounted on   Type    Use%
//	/            ext4     45%
//	/home        ext4     12%
//	/run         tmpfs    1%
//
// Non-"real" filesystem types are filtered out. Mounts are returned sorted by
// mount path for stable display.
func parseDfOutput(s string) ([]hosts.DiskInfo, error) {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	if len(lines) < 1 {
		return nil, fmt.Errorf("df: empty output")
	}
	var out []hosts.DiskInfo
	for i, line := range lines {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		mount, fstype, pcent := fields[0], fields[1], fields[2]
		if !realFSTypes[fstype] {
			continue
		}
		pct, err := strconv.Atoi(strings.TrimSuffix(pcent, "%"))
		if err != nil {
			return nil, fmt.Errorf("df: parse %q: %w", pcent, err)
		}
		out = append(out, hosts.DiskInfo{Mount: mount, FSType: fstype, UsedPct: pct})
	}
	// Stable order by mount path.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j-1].Mount > out[j].Mount; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out, nil
}
