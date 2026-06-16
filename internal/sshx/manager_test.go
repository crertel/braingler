package sshx

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/crertel/braingler/internal/config"
	"golang.org/x/crypto/ssh"
)

func newSigner(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s, string(ssh.MarshalAuthorizedKey(s.PublicKey()))
}

// TestHostKeyCallbackHostCAs covers the per-host multi-CA acceptance set: a host
// cert is accepted iff its signing CA is one of the host's host_cas, and an
// empty host_cas disables verification entirely.
func TestHostKeyCallbackHostCAs(t *testing.T) {
	_, ca1Pub := newSigner(t)  // trusted-but-didn't-sign
	ca2, ca2Pub := newSigner(t) // the actual signer

	// A host key + a host cert signed by ca2.
	hostSigner, _ := newSigner(t)
	cert := &ssh.Certificate{
		Key:             hostSigner.PublicKey(),
		CertType:        ssh.HostCert,
		KeyId:           "test",
		ValidPrincipals: []string{"testhost"},
		ValidAfter:      uint64(time.Now().Add(-time.Minute).Unix()),
		ValidBefore:     uint64(time.Now().Add(time.Hour).Unix()),
	}
	if err := cert.SignCert(rand.Reader, ca2); err != nil {
		t.Fatal(err)
	}

	addr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 22}
	m := &Manager{}

	// Set holds both CAs → cert signed by ca2 is accepted (rotation / multi-CA).
	cb := m.hostKeyCallback(&config.Host{HostCAs: []string{ca1Pub, ca2Pub}})
	if err := cb("testhost:22", addr, cert); err != nil {
		t.Fatalf("cert signed by a CA in the set should be accepted: %v", err)
	}

	// Set holds only ca1 → cert signed by ca2 is rejected.
	cb = m.hostKeyCallback(&config.Host{HostCAs: []string{ca1Pub}})
	if err := cb("testhost:22", addr, cert); err == nil {
		t.Fatal("cert signed by a CA NOT in the set should be rejected")
	}

	// Empty host_cas → no verification: even a bare host key is accepted.
	cb = m.hostKeyCallback(&config.Host{})
	if err := cb("testhost:22", addr, hostSigner.PublicKey()); err != nil {
		t.Fatalf("empty host_cas should disable verification: %v", err)
	}
}
