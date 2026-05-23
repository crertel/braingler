package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeTmp(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "config.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadMinimalValid(t *testing.T) {
	p := writeTmp(t, `{
		"listen": {"address": "127.0.0.1:8080"},
		"hosts": [
			{"name": "h1", "hostname": "h1.local", "mac": "02:00:00:00:00:11", "broadcast": "192.168.1.255",
			 "checks": {"ping": {"enabled": true}}}
		]
	}`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c.PollIntervalSeconds != 7 {
		t.Errorf("default poll = %d, want 7", c.PollIntervalSeconds)
	}
	if c.SSHDefaults.Port != 22 {
		t.Errorf("default ssh port = %d, want 22", c.SSHDefaults.Port)
	}
	if c.HostByName("h1") == nil {
		t.Errorf("h1 not registered")
	}
	if c.Hosts[0].DisplayName != "h1" {
		t.Errorf("display_name default not applied: %q", c.Hosts[0].DisplayName)
	}
}

func TestRejectsBothListenForms(t *testing.T) {
	p := writeTmp(t, `{
		"listen": {"address": "127.0.0.1:8080", "socket": "/tmp/x.sock"},
		"hosts": []
	}`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "set only one") {
		t.Fatalf("want both-listen error, got: %v", err)
	}
}

func TestRejectsMissingListen(t *testing.T) {
	p := writeTmp(t, `{"hosts": []}`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "must set address or socket") {
		t.Fatalf("want missing-listen error, got: %v", err)
	}
}

func TestRejectsBadMAC(t *testing.T) {
	p := writeTmp(t, `{
		"listen": {"address": "127.0.0.1:8080"},
		"hosts": [{"name":"h","hostname":"h.local","mac":"not-a-mac","broadcast":"192.168.1.255","checks":{}}]
	}`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "invalid MAC") {
		t.Fatalf("want MAC error, got: %v", err)
	}
}

func TestRejectsBadBroadcast(t *testing.T) {
	p := writeTmp(t, `{
		"listen": {"address": "127.0.0.1:8080"},
		"hosts": [{"name":"h","hostname":"h.local","mac":"02:00:00:00:00:11","broadcast":"not-an-ip","checks":{}}]
	}`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "invalid broadcast") {
		t.Fatalf("want broadcast error, got: %v", err)
	}
}

func TestRejectsUnknownCheck(t *testing.T) {
	p := writeTmp(t, `{
		"listen": {"address": "127.0.0.1:8080"},
		"hosts": [{"name":"h","hostname":"h.local","mac":"02:00:00:00:00:11","broadcast":"192.168.1.255",
			"checks": {"banana": {"enabled": true}}}]
	}`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), `unknown check "banana"`) {
		t.Fatalf("want unknown-check error, got: %v", err)
	}
}

func TestRejectsDuplicateHostNames(t *testing.T) {
	p := writeTmp(t, `{
		"listen": {"address": "127.0.0.1:8080"},
		"hosts": [
			{"name":"h","hostname":"a","mac":"02:00:00:00:00:11","broadcast":"192.168.1.255","checks":{}},
			{"name":"h","hostname":"b","mac":"04:7c:16:4c:9c:ad","broadcast":"192.168.1.255","checks":{}}
		]
	}`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "duplicate host name") {
		t.Fatalf("want duplicate-host error, got: %v", err)
	}
}

func TestAuthValidation(t *testing.T) {
	p := writeTmp(t, `{
		"listen": {"address": "127.0.0.1:8080"},
		"hosts": [{"name":"h","hostname":"h.local","mac":"02:00:00:00:00:11","broadcast":"192.168.1.255","checks":{}}],
		"auth": {
			"enabled": true,
			"users": [{"username":"u","password_hash":"$2a$10$abc","groups":["nope"]}],
			"groups": {"admin": {"hosts":["ghost"], "actions":["wake","bogus"]}}
		}
	}`)
	_, err := Load(p)
	if err == nil {
		t.Fatal("expected validation errors")
	}
	for _, want := range []string{`unknown group "nope"`, `unknown host "ghost"`, `unknown action "bogus"`} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing %q in error: %v", want, err)
		}
	}
}

func TestEffectiveSSHMerge(t *testing.T) {
	p := writeTmp(t, `{
		"listen": {"address": "127.0.0.1:8080"},
		"ssh_defaults": {"user":"default","key_file":"/tmp/k","port":22,"timeout_seconds":5},
		"hosts": [
			{"name":"override","hostname":"a","mac":"02:00:00:00:00:11","broadcast":"192.168.1.255",
			 "ssh":{"user":"alice","port":2222}, "checks":{}},
			{"name":"inherit","hostname":"b","mac":"04:7c:16:4c:9c:ad","broadcast":"192.168.1.255","checks":{}}
		]
	}`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	got := c.EffectiveSSH(c.HostByName("override"))
	if got.User != "alice" || got.Port != 2222 || got.KeyFile != "/tmp/k" || got.TimeoutSeconds != 5 {
		t.Errorf("override merge wrong: %+v", got)
	}
	got = c.EffectiveSSH(c.HostByName("inherit"))
	if got.User != "default" || got.Port != 22 {
		t.Errorf("inherit wrong: %+v", got)
	}
}

func TestUserCanWildcards(t *testing.T) {
	p := writeTmp(t, `{
		"listen": {"address": "127.0.0.1:8080"},
		"hosts": [
			{"name":"a","hostname":"a","mac":"02:00:00:00:00:11","broadcast":"192.168.1.255","checks":{}},
			{"name":"b","hostname":"b","mac":"04:7c:16:4c:9c:ad","broadcast":"192.168.1.255","checks":{}}
		],
		"auth": {
			"enabled": true,
			"users": [
				{"username":"root","password_hash":"$2a$10$abc","groups":["admin"]},
				{"username":"office","password_hash":"$2a$10$abc","groups":["office"]}
			],
			"groups": {
				"admin": {"hosts":["*"], "actions":["*"]},
				"office": {"hosts":["a"], "actions":["status","wake"]}
			}
		}
	}`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !c.UserCan("root", "b", "shutdown") {
		t.Error("admin should be allowed everything")
	}
	if c.UserCan("office", "b", "status") {
		t.Error("office should not see host b")
	}
	if !c.UserCan("office", "a", "wake") {
		t.Error("office should wake a")
	}
	if c.UserCan("office", "a", "shutdown") {
		t.Error("office must not shutdown")
	}
	if c.UserCan("ghost", "a", "status") {
		t.Error("unknown user must not be allowed")
	}
}

func TestAuthDisabledAllowsAll(t *testing.T) {
	p := writeTmp(t, `{
		"listen": {"address": "127.0.0.1:8080"},
		"hosts": [{"name":"a","hostname":"a","mac":"02:00:00:00:00:11","broadcast":"192.168.1.255","checks":{}}]
	}`)
	c, err := Load(p)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if !c.UserCan("nobody", "a", "shutdown") {
		t.Error("auth disabled should allow everything")
	}
}

func TestRejectsUnknownTopLevelField(t *testing.T) {
	p := writeTmp(t, `{
		"listen": {"address": "127.0.0.1:8080"},
		"hosts": [],
		"surprise": true
	}`)
	_, err := Load(p)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("want unknown-field error, got: %v", err)
	}
}
