package sshca

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newTempCA(t *testing.T) *CA {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ca")
	ca, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func newUserKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return sshPub
}

func TestLoadGeneratesIfMissing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "ca")
	ca, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if ca.PublicKey() == nil {
		t.Fatal("nil pubkey on freshly-generated CA")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("ca file mode = %v, want 0600", info.Mode().Perm())
	}
	// Reload — must produce a CA with the same pubkey.
	ca2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(ca.PublicKey().Marshal()) != string(ca2.PublicKey().Marshal()) {
		t.Error("reload produced a different pubkey")
	}
}

func TestSignUserCertAgentShape(t *testing.T) {
	ca := newTempCA(t)
	userKey := newUserKey(t)
	cert, err := ca.SignUserCert(userKey, UserCertOptions{
		KeyID:            "actor=alice action=shutdown",
		ValidPrincipals:  []string{"maint"},
		TTL:              time.Minute,
		ForceCommand:     "sudo -n shutdown -hP now",
		NoPTY:            true,
		NoPortForwarding: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertType != ssh.UserCert {
		t.Errorf("CertType = %d, want UserCert", cert.CertType)
	}
	if cert.KeyId != "actor=alice action=shutdown" {
		t.Errorf("KeyId mismatch: %q", cert.KeyId)
	}
	if got := cert.Permissions.CriticalOptions["force-command"]; got != "sudo -n shutdown -hP now" {
		t.Errorf("force-command = %q", got)
	}
	if _, hasPTY := cert.Permissions.Extensions["permit-pty"]; hasPTY {
		t.Error("permit-pty should not be set when NoPTY is true")
	}
	if _, hasFwd := cert.Permissions.Extensions["permit-port-forwarding"]; hasFwd {
		t.Error("permit-port-forwarding should not be set when NoPortForwarding is true")
	}
	if _, hasX11 := cert.Permissions.Extensions["permit-X11-forwarding"]; !hasX11 {
		t.Error("permit-X11-forwarding should be set when its No-flag is false")
	}

	// Round-trip through MarshalAuthorizedKey/ParseAuthorizedKey to confirm
	// the cert serializes cleanly and the CA signature verifies.
	line := ssh.MarshalAuthorizedKey(cert)
	pub, _, _, _, err := ssh.ParseAuthorizedKey(line)
	if err != nil {
		t.Fatalf("re-parse cert: %v", err)
	}
	roundTrip, ok := pub.(*ssh.Certificate)
	if !ok {
		t.Fatalf("re-parsed is %T, want *ssh.Certificate", pub)
	}
	if roundTrip.KeyId != cert.KeyId {
		t.Errorf("round-trip KeyId mismatch: %q vs %q", roundTrip.KeyId, cert.KeyId)
	}
	if got := roundTrip.Permissions.CriticalOptions["force-command"]; got != "sudo -n shutdown -hP now" {
		t.Errorf("round-trip force-command lost: %q", got)
	}
	// SignatureKey on the parsed cert must equal the CA pubkey.
	if string(roundTrip.SignatureKey.Marshal()) != string(ca.PublicKey().Marshal()) {
		t.Error("SignatureKey doesn't match CA pubkey")
	}
}

func TestSignUserCertHumanCheckable(t *testing.T) {
	// Human certs (no force-command) pass through Go's ssh.CertChecker, which
	// confirms the CA signature + principal match. Agent certs can't be tested
	// this way because CertChecker rejects "force-command" as unknown, even
	// though sshd handles it natively.
	ca := newTempCA(t)
	userKey := newUserKey(t)
	cert, err := ca.SignUserCert(userKey, UserCertOptions{
		KeyID:           "human=alice",
		ValidPrincipals: []string{"alice", "ops"},
		TTL:             time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return string(k.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}
	if err := checker.CheckCert("alice", cert); err != nil {
		t.Errorf("CheckCert(alice): %v", err)
	}
	if err := checker.CheckCert("ops", cert); err != nil {
		t.Errorf("CheckCert(ops): %v", err)
	}
	if err := checker.CheckCert("eve", cert); err == nil {
		t.Error("CheckCert with wrong principal should fail")
	}
}


func TestSignUserCertRejectsEmptyPrincipals(t *testing.T) {
	ca := newTempCA(t)
	userKey := newUserKey(t)
	if _, err := ca.SignUserCert(userKey, UserCertOptions{TTL: time.Minute}); err == nil {
		t.Error("expected error for empty principals")
	}
}

func TestSignHostCert(t *testing.T) {
	ca := newTempCA(t)
	hostKey := newUserKey(t) // any pubkey works for host cert
	cert, err := ca.SignHostCert(hostKey, HostCertOptions{
		KeyID:           "lab-host",
		ValidPrincipals: []string{"lab-host", "lab-host.local"},
		TTL:             24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cert.CertType != ssh.HostCert {
		t.Errorf("CertType = %d, want HostCert", cert.CertType)
	}
	checker := &ssh.CertChecker{
		IsHostAuthority: func(k ssh.PublicKey, _ string) bool {
			return string(k.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}
	if err := checker.CheckHostKey("lab-host:22", nil, cert); err != nil {
		t.Errorf("CheckHostKey(lab-host): %v", err)
	}
	if err := checker.CheckHostKey("ghost:22", nil, cert); err == nil {
		t.Error("CheckHostKey for wrong host should fail")
	}
}

func TestAuthorizedKeyAndFingerprint(t *testing.T) {
	ca := newTempCA(t)
	ak := ca.AuthorizedKey("braingler-ca")
	if !strings.HasPrefix(ak, "ssh-ed25519 ") || !strings.HasSuffix(ak, " braingler-ca") {
		t.Errorf("AuthorizedKey format: %q", ak)
	}
	fp := ca.Fingerprint()
	if !strings.HasPrefix(fp, "SHA256:") {
		t.Errorf("Fingerprint format: %q", fp)
	}
}

func TestGenerateEphemeralUserKeypair(t *testing.T) {
	pemBytes, pub, err := GenerateEphemeralUserKeypair()
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		t.Fatal("ephemeral private key is not valid PEM")
	}
	if pub.Type() != "ssh-ed25519" {
		t.Errorf("pubkey type = %q, want ssh-ed25519", pub.Type())
	}
	// Round trip: parse the private key, derive its pubkey, check it matches.
	signer, err := ssh.ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	if string(signer.PublicKey().Marshal()) != string(pub.Marshal()) {
		t.Error("derived pubkey does not match returned pubkey")
	}
}

func TestExpiredCertRejected(t *testing.T) {
	ca := newTempCA(t)
	cert, err := ca.SignUserCert(newUserKey(t), UserCertOptions{
		ValidPrincipals: []string{"a"},
		TTL:             time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Cert is valid for 1s; force it to be expired by mutating ValidBefore.
	cert.ValidBefore = uint64(time.Now().Add(-time.Minute).Unix())
	checker := &ssh.CertChecker{
		IsUserAuthority: func(k ssh.PublicKey) bool {
			return string(k.Marshal()) == string(ca.PublicKey().Marshal())
		},
	}
	if err := checker.CheckCert("a", cert); err == nil {
		t.Error("expired cert should be rejected")
	}
}
