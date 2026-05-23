package monitor

import (
	"testing"
	"time"

	"github.com/crertel/braingler/internal/hosts"
)

func TestParseUptime(t *testing.T) {
	d, err := parseUptime("12345.67 23456.78\n")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Duration(12345.67 * float64(time.Second))
	if d != want {
		t.Errorf("got %v, want %v", d, want)
	}

	if _, err := parseUptime(""); err == nil {
		t.Error("empty input should error")
	}
	if _, err := parseUptime("oops\n"); err == nil {
		t.Error("non-numeric should error")
	}
}

func TestParseLoad(t *testing.T) {
	got, err := parseLoad("0.10 0.20 0.30 1/200 12345\n")
	if err != nil {
		t.Fatal(err)
	}
	want := hosts.LoadInfo{One: 0.10, Five: 0.20, Fifteen: 0.30}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}

	if _, err := parseLoad("0.1 0.2\n"); err == nil {
		t.Error("short input should error")
	}
}

func TestParseMemInfo(t *testing.T) {
	in := `MemTotal:       16384000 kB
MemFree:         1024000 kB
MemAvailable:   12345678 kB
Buffers:          200000 kB
`
	got, err := parseMemInfo(in)
	if err != nil {
		t.Fatal(err)
	}
	want := hosts.MemInfo{TotalKB: 16384000, AvailableKB: 12345678}
	if got != want {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestParseMemInfoFallsBackToMemFree(t *testing.T) {
	in := `MemTotal:       16384000 kB
MemFree:         1024000 kB
Buffers:          200000 kB
`
	got, err := parseMemInfo(in)
	if err != nil {
		t.Fatal(err)
	}
	if got.AvailableKB != 1024000 {
		t.Errorf("want fallback to MemFree=1024000, got %d", got.AvailableKB)
	}
}

func TestParseMemInfoMissingTotal(t *testing.T) {
	if _, err := parseMemInfo("MemFree: 1024 kB"); err == nil {
		t.Error("missing MemTotal should error")
	}
}

func TestParseDfOutput(t *testing.T) {
	in := `Mounted on               Type    Use%
/                        ext4     45%
/home                    btrfs    12%
/run                     tmpfs     1%
/dev                     devtmpfs  0%
/boot/efi                vfat     22%
/mnt/zpool               zfs      80%
`
	got, err := parseDfOutput(in)
	if err != nil {
		t.Fatal(err)
	}
	want := []hosts.DiskInfo{
		{Mount: "/", FSType: "ext4", UsedPct: 45},
		{Mount: "/boot/efi", FSType: "vfat", UsedPct: 22},
		{Mount: "/home", FSType: "btrfs", UsedPct: 12},
		{Mount: "/mnt/zpool", FSType: "zfs", UsedPct: 80},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d disks, want %d (got=%+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("disk %d: got %+v want %+v", i, got[i], want[i])
		}
	}
}
