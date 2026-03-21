package proxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"golang.org/x/crypto/ssh"
)

func TestProxy(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Proxy Suite")
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// testSSHServer is a minimal in-process SSH server that:
//   - listens on a random local port
//   - authenticates any credential
//   - exposes an onConn hook so tests can inject server-side behaviour
type testSSHServer struct {
	addr      string
	serverCfg *ssh.ServerConfig

	// onConn is called for every accepted connection.  If nil the server
	// discards everything.
	onConn func(conn ssh.Conn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request)
}

func newTestSSHServer() *testSSHServer {
	signer := generateSigner()
	cfg := &ssh.ServerConfig{
		NoClientAuth: true,
		PasswordCallback: func(_ ssh.ConnMetadata, _ []byte) (*ssh.Permissions, error) {
			return &ssh.Permissions{}, nil
		},
	}
	cfg.AddHostKey(signer)
	return &testSSHServer{serverCfg: cfg}
}

// start listens on a random port and serves connections in the background.
func (s *testSSHServer) start(t GinkgoTInterface) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	Expect(err).NotTo(HaveOccurred())
	s.addr = ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go s.handleConn(conn)
		}
	}()

	DeferCleanup(ln.Close)
}

func (s *testSSHServer) handleConn(conn net.Conn) {
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, s.serverCfg)
	if err != nil {
		return
	}
	defer func() { _ = sshConn.Close() }()

	if s.onConn != nil {
		s.onConn(sshConn, chans, reqs)
		return
	}
	// Default: discard everything
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		go func(ch ssh.NewChannel) {
			c, reqs, err := ch.Accept()
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			_ = c.Close()
		}(newCh)
	}
}

// dialTarget dials addr with a bare ssh.NewClientConn and returns the same
// tuple as connectToTarget, so tests can feed it into proxySSHConnection.
func dialTarget(addr string) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
	netConn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, nil, nil, err
	}
	cfg := &ssh.ClientConfig{
		User:            "test",
		Auth:            []ssh.AuthMethod{ssh.Password("test")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	return ssh.NewClientConn(netConn, addr, cfg)
}

// generateSigner creates a fresh ed25519 SSH signer for test servers.
func generateSigner() ssh.Signer {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	Expect(err).NotTo(HaveOccurred())
	s, err := ssh.NewSignerFromKey(priv)
	Expect(err).NotTo(HaveOccurred())
	return s
}

// portFromAddr parses the port number from a "host:port" listener address.
func portFromAddr(addr string) int {
	_, portStr, err := net.SplitHostPort(addr)
	Expect(err).NotTo(HaveOccurred())
	var port int
	_, err = fmt.Sscanf(portStr, "%d", &port)
	Expect(err).NotTo(HaveOccurred())
	return port
}
