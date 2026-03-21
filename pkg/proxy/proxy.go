package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/schrodit/ssh-proxy/pkg/config"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/ssh"
)

var tracer = otel.Tracer("ssh-proxy")

const (
	openSSHHostKeysRequest      = "hostkeys-00@openssh.com"
	openSSHHostKeysProveRequest = "hostkeys-prove-00@openssh.com"
)

// resolvedTarget contains all resolved values needed to connect to a target SSH server.
// This decouples the connection logic from the config types and template resolution.
type resolvedTarget struct {
	Host            string
	Port            int
	User            string
	AuthType        string
	AuthPassword    string
	AuthKeyPath     string
	HostKeyCallback ssh.HostKeyCallback
}

// SSHProxy represents an SSH proxy server
type SSHProxy struct {
	configManager *config.ConfigManager
	host          string
	port          int
	hostKeyPath   string
	hostKey       ssh.Signer
	serverConfig  *ssh.ServerConfig
}

type proxiedSSHConnection struct {
	conn  ssh.Conn
	chans <-chan ssh.NewChannel
	reqs  <-chan *ssh.Request
}

// New creates a new SSH proxy instance
func New(configManager *config.ConfigManager, host string, port int, hostKeyPath string) *SSHProxy {
	proxy := &SSHProxy{
		configManager: configManager,
		host:          host,
		port:          port,
		hostKeyPath:   hostKeyPath,
	}

	// Load or generate host key
	hostKey, err := proxy.loadOrGenerateHostKey()
	if err != nil {
		slog.Error("Failed to load host key", "error", err)
		os.Exit(1)
	}
	proxy.hostKey = hostKey

	// Configure SSH server
	proxy.serverConfig = &ssh.ServerConfig{
		PasswordCallback:            proxy.handlePasswordAuth,
		PublicKeyCallback:           proxy.handlePublicKeyAuth,
		KeyboardInteractiveCallback: proxy.handleKeyboardInteractiveAuth,
	}
	proxy.serverConfig.AddHostKey(hostKey)

	return proxy
}

// Start starts the SSH proxy server
func (p *SSHProxy) Start() error {
	addr := fmt.Sprintf("%s:%d", p.host, p.port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", addr, err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			slog.Error("Failed to close listener", "error", err)
		}
	}()

	slog.Info("SSH proxy server listening", "address", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			slog.Error("Failed to accept connection", "error", err)
			continue
		}

		go p.handleConnection(conn)
	}
}

func (p *SSHProxy) handleConnection(conn net.Conn) {
	defer func() {
		if err := conn.Close(); shouldLogConnCloseError(err) {
			slog.Error("Failed to close client connection", "error", err)
		}
		slog.Info("Client connection closed")
	}()

	// Perform SSH handshake
	sshConn, chans, reqs, err := ssh.NewServerConn(conn, p.serverConfig)
	if err != nil {
		slog.Error("Failed to handshake", "error", err)
		return
	}
	defer func() {
		if err := sshConn.Close(); shouldLogConnCloseError(err) {
			slog.Error("Failed to close SSH connection", "error", err)
		}
		slog.Info("SSH connection closed")
	}()

	// Get the authenticated username
	// TODO: the target route can simply be cached since its deterministic.
	//       Consider when we run into perf issues.
	username := sshConn.User()
	match := p.configManager.FindRoute(username)
	if match == nil {
		slog.Warn("No route found for user", "username", username)
		return
	}
	route := match.Route

	// Resolve host template if applicable
	resolvedHost, err := config.ResolveHost(route.Target.Host, match, username)
	if err != nil {
		slog.Error("Failed to resolve target host template", "error", err, "username", username)
		return
	}

	target := &resolvedTarget{
		Host:         resolvedHost,
		Port:         route.Target.Port,
		User:         route.Target.User,
		AuthType:     route.Target.Auth.Type,
		AuthPassword: route.Target.Auth.Password,
		AuthKeyPath:  route.Target.Auth.KeyPath,
	}

	// Build host key callback
	hostKeyCallback, err := buildHostKeyCallback(route.Target)
	if err != nil {
		slog.Error("Failed to build host key callback", "error", err, "username", username)
		return
	}
	target.HostKeyCallback = hostKeyCallback

	slog.Info("User authenticated, routing to target", "username", username, "target_host", target.Host, "target_port", target.Port)

	// Establish connection to target SSH server
	targetConn, err := p.connectToTarget(target)
	if err != nil {
		slog.Error("Failed to connect to target", "error", err)
		return
	}
	defer func() {
		if err := targetConn.conn.Close(); shouldLogConnCloseError(err) {
			slog.Error("Failed to close target connection", "error", err)
		}
		slog.Info("Target connection closed", "username", username)
	}()

	slog.Info("Session started", "username", username)

	// Handle SSH channels and requests
	p.proxySSHConnection(sshConn, targetConn, chans, reqs)

	slog.Info("Session ended", "username", username)
}

func (p *SSHProxy) connectToTarget(target *resolvedTarget) (*proxiedSSHConnection, error) {
	targetAddr := net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port))

	// Configure client based on target auth type
	var auth []ssh.AuthMethod
	switch target.AuthType {
	case "password":
		auth = []ssh.AuthMethod{
			ssh.Password(target.AuthPassword),
		}
	case "key":
		key, err := loadPrivateKey(target.AuthKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load private key: %w", err)
		}
		auth = []ssh.AuthMethod{
			ssh.PublicKeys(key),
		}
	default:
		return nil, fmt.Errorf("unsupported target auth type: %s", target.AuthType)
	}

	config := &ssh.ClientConfig{
		User:            target.User,
		Auth:            auth,
		HostKeyCallback: target.HostKeyCallback,
	}

	rawConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to target SSH server: %w", err)
	}

	conn, chans, reqs, err := ssh.NewClientConn(rawConn, targetAddr, config)
	if err != nil {
		if closeErr := rawConn.Close(); closeErr != nil {
			slog.Error("Failed to close raw target connection after handshake error", "error", closeErr)
		}
		return nil, fmt.Errorf("failed to connect to target SSH server: %w", err)
	}

	return &proxiedSSHConnection{
		conn:  conn,
		chans: chans,
		reqs:  reqs,
	}, nil
}

// buildHostKeyCallback creates an ssh.HostKeyCallback based on the target configuration.
// Config validation guarantees that either host_key or insecure is set.
func buildHostKeyCallback(target config.Target) (ssh.HostKeyCallback, error) {
	if target.HostKey != "" {
		expected, _, _, _, err := ssh.ParseAuthorizedKey([]byte(target.HostKey))
		if err != nil {
			return nil, fmt.Errorf("failed to parse target host_key %q: %w", target.HostKey, err)
		}
		return ssh.FixedHostKey(expected), nil
	}

	// insecure must be true at this point (enforced by config validation)
	return ssh.InsecureIgnoreHostKey(), nil
}

func (p *SSHProxy) proxySSHConnection(clientConn ssh.Conn, targetConn *proxiedSSHConnection, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	var wg sync.WaitGroup
	var channelWg sync.WaitGroup

	// Close the peer connection when either side disconnects so both request/channel
	// streams terminate and the proxy can shut down cleanly.
	go func() {
		_ = clientConn.Wait()
		_ = targetConn.conn.Close()
	}()
	go func() {
		_ = targetConn.conn.Wait()
		_ = clientConn.Close()
	}()

	// Handle incoming channels from the client.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for newChannel := range chans {
			channelWg.Add(1)
			go func(channel ssh.NewChannel) {
				defer channelWg.Done()
				p.handleChannel("client", clientConn, "target", targetConn.conn, channel)
			}(newChannel)
		}
	}()

	// Handle incoming channels from the target.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for newChannel := range targetConn.chans {
			channelWg.Add(1)
			go func(channel ssh.NewChannel) {
				defer channelWg.Done()
				p.handleChannel("target", targetConn.conn, "client", clientConn, channel)
			}(newChannel)
		}
	}()

	// Handle incoming requests from the client.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range reqs {
			p.handleRequest("client", "target", targetConn.conn, req)
		}
	}()

	// Handle incoming requests from the target.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range targetConn.reqs {
			p.handleRequest("target", "client", clientConn, req)
		}
	}()

	wg.Wait()
	channelWg.Wait()
}

func (p *SSHProxy) handleChannel(sourceName string, sourceConn ssh.Conn, destinationName string, destinationConn ssh.Conn, newChannel ssh.NewChannel) {
	_, span := tracer.Start(context.Background(), "handleChannel")
	defer span.End()
	log := slog.With(
		"session_id", span.SpanContext().TraceID().String(),
		"channel_type", newChannel.ChannelType(),
		"source", sourceName,
		"destination", destinationName,
	)

	// Open the corresponding channel on the destination side first so we can reject
	// the incoming channel cleanly if the peer does not support it.
	destinationChannel, destinationReqs, err := destinationConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
	if err != nil {
		log.Error("Failed to open channel on destination", "error", err)
		if err := newChannel.Reject(ssh.Prohibited, "destination rejected channel"); err != nil {
			slog.Error("Failed to reject channel", "error", err)
		}
		return
	}
	defer func() {
		logChannelCloseError(log, "Failed to close destination channel", destinationChannel.Close())
		log.Debug("Destination channel closed")
	}()

	// Accept the channel from the source side.
	sourceChannel, sourceReqs, err := newChannel.Accept()
	if err != nil {
		log.Error("Failed to accept channel", "error", err)
		return
	}
	defer func() {
		logChannelCloseError(log, "Failed to close source channel", sourceChannel.Close())
		log.Debug("Source channel closed")
	}()

	log.Debug("Channel opened")

	destinationWg := sync.WaitGroup{}
	sourceWg := sync.WaitGroup{}

	// Proxy data between channels with proper EOF handling
	sourceWg.Go(func() {
		defer func() {
			logChannelCloseError(log, "Failed to close write on destination channel", destinationChannel.CloseWrite())
			log.Debug("Source to destination data stream closed")
		}()
		_, err := io.Copy(destinationChannel, sourceChannel)
		if err != nil && err != io.EOF {
			log.Error("Error copying source to destination", "error", err)
		}
	})
	destinationWg.Go(func() {
		defer func() {
			logChannelCloseError(log, "Failed to close write on source channel", sourceChannel.CloseWrite())
			log.Debug("Destination to source data stream closed")
		}()
		_, err := io.Copy(sourceChannel, destinationChannel)
		if err != nil && err != io.EOF {
			log.Error("Error copying destination to source", "error", err)
		}
	})

	// Proxy requests between channels
	sourceWg.Go(func() {
		defer func() {
			log.Debug("Source to destination request stream closed")
		}()
		for req := range sourceReqs {
			log.Debug("Forwarding request from source to destination", "request_type", req.Type)
			reply, err := destinationChannel.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			if req.WantReply {
				if err := req.Reply(reply, nil); err != nil {
					log.Error("Failed to reply to source request", "error", err)
				}
			}
		}
	})
	destinationWg.Go(func() {
		defer func() {
			log.Debug("Destination to source request stream closed")
		}()
		for req := range destinationReqs {
			log.Debug("Forwarding request from destination to source", "request_type", req.Type)
			reply, err := sourceChannel.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Error("Failed to forward channel request to source", "error", err)
				return
			}
			if req.WantReply {
				if err := req.Reply(reply, nil); err != nil {
					log.Error("Failed to reply to destination request", "error", err)
				}
			}
		}
	})

	wg := sync.WaitGroup{}
	wg.Go(func() {
		defer func() {
			logChannelCloseError(log, "Failed to close source channel in wait group", sourceChannel.Close())
		}()
		destinationWg.Wait()
	})
	wg.Go(func() {
		defer func() {
			logChannelCloseError(log, "Failed to close destination channel in wait group", destinationChannel.Close())
		}()
		sourceWg.Wait()
	})
	wg.Wait()
}

func logChannelCloseError(log *slog.Logger, message string, err error) {
	if err == nil || err == io.EOF || errors.Is(err, net.ErrClosed) {
		return
	}
	log.Error(message, "error", err)
}

func shouldLogConnCloseError(err error) bool {
	return err != nil && err != io.EOF && !errors.Is(err, net.ErrClosed)
}

func shouldHandleRequestLocally(req *ssh.Request) (handled bool, replyOK bool, replyPayload []byte) {
	switch req.Type {
	case openSSHHostKeysRequest:
		// UpdateHostKeys is scoped to the proxy's server identity, so forwarding it to
		// the target would advertise or validate the wrong host keys.
		return true, false, nil
	case openSSHHostKeysProveRequest:
		// We do not advertise UpdateHostKeys today, so reject proofs locally instead of
		// asking the target to prove ownership of keys the client did not negotiate with.
		return true, false, nil
	default:
		return false, false, nil
	}
}

func (p *SSHProxy) handleRequest(sourceName string, destinationName string, destinationConn ssh.Conn, req *ssh.Request) {
	slog.Debug("Handle request", "source", sourceName, "destination", destinationName, "request_type", req.Type)
	if handled, reply, replyPayload := shouldHandleRequestLocally(req); handled {
		slog.Debug("Handled request locally", "source", sourceName, "destination", destinationName, "request_type", req.Type, "want_reply", req.WantReply)
		if req.WantReply {
			if err := req.Reply(reply, replyPayload); err != nil {
				slog.Error("Failed to reply to local request", "error", err, "request_type", req.Type)
			}
		}
		return
	}

	reply, replyPayload, err := destinationConn.SendRequest(req.Type, req.WantReply, req.Payload)
	if err != nil {
		slog.Error("Failed to forward request", "error", err)
		if req.WantReply {
			if err := req.Reply(false, nil); err != nil {
				slog.Error("Failed to reply with error to request", "error", err)
			}
		}
		return
	}
	if req.WantReply {
		if err := req.Reply(reply, replyPayload); err != nil {
			slog.Error("Failed to reply to request", "error", err)
		}
	}
}

func (p *SSHProxy) loadOrGenerateHostKey() (ssh.Signer, error) {
	// Try to load from specified host key path
	if p.hostKeyPath != "" {
		keyBytes, err := os.ReadFile(p.hostKeyPath)
		if err == nil {
			return ssh.ParsePrivateKey(keyBytes)
		}
		slog.Warn("Could not load host key, will generate new one", "path", p.hostKeyPath, "error", err)
	}

	// Try to load from default file
	keyPath := "host_key"
	keyBytes, err := os.ReadFile(keyPath)
	if err == nil {
		return ssh.ParsePrivateKey(keyBytes)
	}

	// Generate new key
	slog.Info("Generating new host key")
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Save key to file
	if err := os.WriteFile(keyPath, privateKeyPEM, 0600); err != nil {
		slog.Warn("Failed to save host key", "error", err)
	}

	return ssh.ParsePrivateKey(privateKeyPEM)
}

func loadPrivateKey(keyPath string) (ssh.Signer, error) {
	keyBytes, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	signer, err := ssh.ParsePrivateKey(keyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return signer, nil
}
