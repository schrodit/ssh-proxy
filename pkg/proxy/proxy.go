package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"sync"

	"github.com/schrodit/ssh-proxy/pkg/config"
	"github.com/schrodit/ssh-proxy/pkg/types"
	"go.opentelemetry.io/otel"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

var tracer = otel.Tracer("ssh-proxy")

const maxKeyboardInteractiveRounds = 10

type keyboardInteractiveChallenger interface {
	Challenge(name, instruction string, questions []string, echos []bool) ([]string, error)
}

type sshKeyboardInteractiveChallenger struct {
	challenge ssh.KeyboardInteractiveChallenge
}

func (c sshKeyboardInteractiveChallenger) Challenge(name, instruction string, questions []string, echos []bool) ([]string, error) {
	return c.challenge(name, instruction, questions, echos)
}

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
		if err := conn.Close(); err != nil {
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
		if err := sshConn.Close(); err != nil {
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
	targetConn, targetChans, targetReqs, err := p.connectToTarget(target)
	if err != nil {
		slog.Error("Failed to connect to target", "error", err)
		return
	}
	defer func() {
		if err := targetConn.Close(); err != nil {
			slog.Error("Failed to close target connection", "error", err)
		}
		slog.Info("Target connection closed", "username", username)
	}()

	slog.Info("Session started", "username", username)

	// Handle SSH channels and requests
	p.proxySSHConnection(sshConn, targetConn, chans, reqs, targetChans, targetReqs)

	slog.Info("Session ended", "username", username)
}

func (p *SSHProxy) handlePasswordAuth(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	username := conn.User()
	match := p.configManager.FindRoute(username)
	slog.Debug("Password auth attempt", "username", username)
	if match == nil {
		return nil, fmt.Errorf("user not found")
	}
	route := match.Route

	// Check all auth methods for password authentication
	for _, authMethod := range route.Auth {
		// Handle external auth (webhook)
		if authMethod.Type == "external_auth" && authMethod.ExternalAuth != nil {
			allowed, err := callWebhookAuth(authMethod.ExternalAuth, &types.WebhookPasswordAuthRequest{
				WebhookAuthRequest: types.WebhookAuthRequest{
					Username: username,
					AuthType: types.WebhookAuthTypePassword,
				},
				Password: string(password),
			})
			if err != nil {
				slog.Error("External auth request failed", "error", err, "username", username)
				continue
			}
			if allowed {
				slog.Info("External auth password authentication successful", "username", username)
				return permissionsForUser(username), nil
			}
			slog.Debug("External auth denied password authentication", "username", username)
			continue
		}

		if authMethod.Type != "password" {
			continue
		}

		// Determine which password to verify against
		passwordToVerify := authMethod.Password
		if authMethod.PasswordHash != "" {
			passwordToVerify = authMethod.PasswordHash
		}

		// Skip if no password is configured
		if passwordToVerify == "" {
			continue
		}

		// Verify password
		if verifyPassword(string(password), passwordToVerify, authMethod.HashType) {
			slog.Info("Password authentication successful", "username", username)
			return permissionsForUser(username), nil
		}
	}

	slog.Warn("Password authentication failed", "username", username)
	return nil, fmt.Errorf("password authentication failed")
}

func (p *SSHProxy) handlePublicKeyAuth(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	username := conn.User()
	match := p.configManager.FindRoute(username)
	slog.Debug("Public key auth attempt", "username", username)
	if match == nil {
		return nil, fmt.Errorf("user not found")
	}
	route := match.Route

	// Check all auth methods for public key authentication
	for _, authMethod := range route.Auth {
		// Handle external auth (webhook)
		if authMethod.Type == "external_auth" && authMethod.ExternalAuth != nil {
			allowed, err := callWebhookAuth(authMethod.ExternalAuth, &types.WebhookPublicKeyAuthRequest{
				WebhookAuthRequest: types.WebhookAuthRequest{
					Username: username,
					AuthType: types.WebhookAuthTypePublicKey,
				},
				PublicKey: string(ssh.MarshalAuthorizedKey(key)),
			})
			if err != nil {
				slog.Error("External auth request failed", "error", err, "username", username)
				continue
			}
			if allowed {
				slog.Info("External auth public key authentication successful", "username", username)
				return permissionsForUser(username), nil
			}
			slog.Debug("External auth denied public key authentication", "username", username)
			continue
		}

		if authMethod.Type != "key" {
			continue
		}

		// Check if the provided key matches any authorized key in this auth method
		for _, authorizedKey := range authMethod.AuthorizedKeys {
			if comparePublicKeys(key, authorizedKey) {
				slog.Info("Public key authentication successful", "username", username)
				return permissionsForUser(username), nil
			}
		}
	}

	slog.Warn("Public key authentication failed", "username", username)
	return nil, fmt.Errorf("public key authentication failed")
}

func (p *SSHProxy) handleKeyboardInteractiveAuth(conn ssh.ConnMetadata, client ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	username := conn.User()
	match := p.configManager.FindRoute(username)
	slog.Debug("Keyboard-interactive auth attempt", "username", username)
	if match == nil {
		return nil, fmt.Errorf("user not found")
	}

	challenger := sshKeyboardInteractiveChallenger{challenge: client}

	for _, authMethod := range match.Route.Auth {
		if authMethod.Type != "keyboard_interactive" || authMethod.ExternalAuth == nil {
			continue
		}

		perms, err := authenticateKeyboardInteractive(username, conn.SessionID(), authMethod.ExternalAuth, challenger)
		if err != nil {
			slog.Error("Keyboard-interactive authentication failed", "error", err, "username", username)
			continue
		}
		if perms != nil {
			slog.Info("Keyboard-interactive authentication successful", "username", username)
			return perms, nil
		}
	}

	slog.Warn("Keyboard-interactive authentication failed", "username", username)
	return nil, fmt.Errorf("keyboard-interactive authentication failed")
}

func authenticateKeyboardInteractive(username string, sessionID []byte, cfg *config.WebhookConfig, challenger keyboardInteractiveChallenger) (*ssh.Permissions, error) {
	req := &types.WebhookKeyboardInteractiveAuthRequest{
		WebhookAuthRequest: types.WebhookAuthRequest{
			Username: username,
			AuthType: types.WebhookAuthTypeKeyboardInteractive,
		},
		SessionID: hex.EncodeToString(sessionID),
	}

	for round := 0; round < maxKeyboardInteractiveRounds; round++ {
		req.ChallengeRound = round

		challengeResp, allowed, err := callKeyboardInteractiveWebhook(cfg, req)
		if err != nil {
			return nil, err
		}
		if allowed {
			return permissionsForUser(username), nil
		}
		if challengeResp == nil {
			return nil, nil
		}
		if len(challengeResp.Questions) == 0 {
			return nil, fmt.Errorf("keyboard-interactive webhook returned no questions")
		}

		echos, err := normalizeChallengeEchos(challengeResp)
		if err != nil {
			return nil, err
		}

		answers, err := challenger.Challenge(challengeResp.Name, challengeResp.Instruction, challengeResp.Questions, echos)
		if err != nil {
			return nil, fmt.Errorf("collecting keyboard-interactive answers: %w", err)
		}

		req.Answers = answers
	}

	return nil, fmt.Errorf("keyboard-interactive authentication exceeded %d challenge rounds", maxKeyboardInteractiveRounds)
}

func normalizeChallengeEchos(challenge *types.WebhookKeyboardInteractiveResponse) ([]bool, error) {
	if len(challenge.Echos) == 0 {
		return make([]bool, len(challenge.Questions)), nil
	}
	if len(challenge.Echos) != len(challenge.Questions) {
		return nil, fmt.Errorf("keyboard-interactive webhook returned %d echo flags for %d questions", len(challenge.Echos), len(challenge.Questions))
	}
	return challenge.Echos, nil
}

func permissionsForUser(username string) *ssh.Permissions {
	return &ssh.Permissions{
		Extensions: map[string]string{
			"username": username,
		},
	}
}

func (p *SSHProxy) connectToTarget(target *resolvedTarget) (ssh.Conn, <-chan ssh.NewChannel, <-chan *ssh.Request, error) {
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
			return nil, nil, nil, fmt.Errorf("failed to load private key: %w", err)
		}
		auth = []ssh.AuthMethod{
			ssh.PublicKeys(key),
		}
	default:
		return nil, nil, nil, fmt.Errorf("unsupported target auth type: %s", target.AuthType)
	}

	clientConfig := &ssh.ClientConfig{
		User:            target.User,
		Auth:            auth,
		HostKeyCallback: target.HostKeyCallback,
	}

	// Use NewClientConn instead of Dial so we receive server-initiated channels
	// (e.g. X11, direct-tcpip) rather than having them silently rejected.
	netConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to connect to target SSH server: %w", err)
	}

	conn, chans, reqs, err := ssh.NewClientConn(netConn, targetAddr, clientConfig)
	if err != nil {
		if err := netConn.Close(); err != nil {
			slog.Error("Failed to close network connection after SSH handshake failure", "error", err)
		}
		return nil, nil, nil, fmt.Errorf("failed to establish SSH connection to target: %w", err)
	}

	return conn, chans, reqs, nil
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

func (p *SSHProxy) proxySSHConnection(
	clientConn ssh.Conn,
	targetConn ssh.Conn,
	chans <-chan ssh.NewChannel,
	reqs <-chan *ssh.Request,
	targetChans <-chan ssh.NewChannel,
	targetReqs <-chan *ssh.Request,
) {
	var wg sync.WaitGroup

	// Handle channels from client → target
	wg.Add(1)
	go func() {
		defer wg.Done()
		for newChannel := range chans {
			p.handleChannel(clientConn, targetConn, newChannel)
		}
	}()

	// Handle channels from target → client (e.g. X11 forwarding)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for newChannel := range targetChans {
			p.handleReverseChannel(clientConn, newChannel)
		}
	}()

	// Handle global requests from client → target
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range reqs {
			p.handleRequest(targetConn, req)
		}
	}()

	// Handle global requests from target → client
	wg.Add(1)
	go func() {
		defer wg.Done()
		for req := range targetReqs {
			p.handleRequest(clientConn, req)
		}
	}()

	wg.Wait()
}

// proxyChannels bidirectionally proxies data and per-channel requests between a
// client and target SSH channel pair. It blocks until both sides are done.
func proxyChannels(clientChannel, targetChannel ssh.Channel, clientReqs, targetReqs <-chan *ssh.Request, log *slog.Logger) {
	targetWg := sync.WaitGroup{}
	clientWg := sync.WaitGroup{}

	clientWg.Go(func() {
		defer func() {
			if err := targetChannel.CloseWrite(); err != nil {
				log.Error("Failed to close write on target channel", "error", err)
			}
			log.Info("Client to target data stream closed")
		}()
		_, err := io.Copy(targetChannel, clientChannel)
		if err != nil && err != io.EOF {
			log.Error("Error copying client to target", "error", err)
		}
	})
	targetWg.Go(func() {
		defer func() {
			if err := clientChannel.CloseWrite(); err != nil {
				log.Error("Failed to close write on client channel", "error", err)
			}
			log.Debug("Target to client data stream closed")
		}()
		_, err := io.Copy(clientChannel, targetChannel)
		if err != nil && err != io.EOF {
			log.Error("Error copying target to client", "error", err)
		}
	})

	clientWg.Go(func() {
		defer log.Debug("Client to target request stream closed")
		for req := range clientReqs {
			log.Debug("Forwarding request from client to target", "request_type", req.Type)
			reply, err := targetChannel.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				return
			}
			if req.WantReply {
				if err := req.Reply(reply, nil); err != nil {
					log.Error("Failed to reply to client request", "error", err)
				}
			}
		}
	})
	targetWg.Go(func() {
		defer log.Debug("Target to client request stream closed")
		for req := range targetReqs {
			log.Debug("Forwarding request from target to client", "request_type", req.Type)
			reply, err := clientChannel.SendRequest(req.Type, req.WantReply, req.Payload)
			if err != nil {
				log.Error("Failed to forward request to client", "error", err)
				return
			}
			if req.WantReply {
				if err := req.Reply(reply, nil); err != nil {
					log.Error("Failed to reply to target request", "error", err)
				}
			}
		}
	})

	wg := sync.WaitGroup{}
	wg.Go(func() {
		defer func() {
			if err := clientChannel.Close(); err != nil {
				log.Error("Failed to close client channel", "error", err)
			}
		}()
		targetWg.Wait()
	})
	wg.Go(func() {
		defer func() {
			if err := targetChannel.Close(); err != nil {
				log.Error("Failed to close target channel", "error", err)
			}
		}()
		clientWg.Wait()
	})
	wg.Wait()
}

func (p *SSHProxy) handleChannel(clientConn ssh.Conn, targetConn ssh.Conn, newChannel ssh.NewChannel) {
	_, span := tracer.Start(context.Background(), "handleChannel")
	defer span.End()
	log := slog.With("session_id", span.SpanContext().TraceID().String())

	// Open corresponding channel on target
	targetChannel, targetReqs, err := targetConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
	if err != nil {
		slog.Error("Failed to open channel on target", "error", err)
		if err := newChannel.Reject(ssh.Prohibited, "target rejected channel"); err != nil {
			slog.Error("Failed to reject channel", "error", err)
		}
		return
	}

	// Accept the channel from client
	clientChannel, clientReqs, err := newChannel.Accept()
	if err != nil {
		log.Error("Failed to accept channel", "error", err)
		if err := targetChannel.Close(); err != nil {
			log.Error("Failed to close target channel after accept failure", "error", err)
		}
		return
	}

	log.Debug("Channel opened", "channel_type", newChannel.ChannelType())
	proxyChannels(clientChannel, targetChannel, clientReqs, targetReqs, log)
	log.Debug("Channel closed", "channel_type", newChannel.ChannelType())
}

// handleReverseChannel handles channels opened by the target server and forwards them
// to the client. This is required for X11 forwarding and reverse port forwarding,
// where the target SSH server initiates a channel back through the proxy.
func (p *SSHProxy) handleReverseChannel(clientConn ssh.Conn, newChannel ssh.NewChannel) {
	_, span := tracer.Start(context.Background(), "handleReverseChannel")
	defer span.End()
	log := slog.With("session_id", span.SpanContext().TraceID().String())

	log.Debug("Target opened reverse channel", "channel_type", newChannel.ChannelType())

	// Open corresponding channel on client first; if the client rejects it,
	// reject the target's request too.
	clientChannel, clientReqs, err := clientConn.OpenChannel(newChannel.ChannelType(), newChannel.ExtraData())
	if err != nil {
		log.Error("Failed to open reverse channel on client", "error", err, "channel_type", newChannel.ChannelType())
		if err := newChannel.Reject(ssh.Prohibited, "client rejected channel"); err != nil {
			log.Error("Failed to reject reverse channel", "error", err)
		}
		return
	}

	// Accept the channel from the target
	targetChannel, targetReqs, err := newChannel.Accept()
	if err != nil {
		log.Error("Failed to accept reverse channel from target", "error", err)
		if err := clientChannel.Close(); err != nil {
			log.Error("Failed to close client channel after accept failure", "error", err)
		}
		return
	}

	log.Debug("Reverse channel opened", "channel_type", newChannel.ChannelType())
	proxyChannels(clientChannel, targetChannel, clientReqs, targetReqs, log)
	log.Debug("Reverse channel closed", "channel_type", newChannel.ChannelType())
}

func (p *SSHProxy) handleRequest(targetConn ssh.Conn, req *ssh.Request) {
	slog.Debug("Handle request", "request_type", req.Type)
	reply, replyPayload, err := targetConn.SendRequest(req.Type, req.WantReply, req.Payload)
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

// comparePublicKeys compares a provided SSH public key with an authorized key string
func comparePublicKeys(providedKey ssh.PublicKey, authorizedKeyStr string) bool {
	// Parse the authorized key string
	authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyStr))
	if err != nil {
		slog.Error("Failed to parse authorized key", "error", err)
		return false
	}

	// Compare the key types
	if providedKey.Type() != authorizedKey.Type() {
		return false
	}

	// Compare the key data
	providedKeyData := providedKey.Marshal()
	authorizedKeyData := authorizedKey.Marshal()

	// Compare byte arrays
	if len(providedKeyData) != len(authorizedKeyData) {
		return false
	}

	for i := 0; i < len(providedKeyData); i++ {
		if providedKeyData[i] != authorizedKeyData[i] {
			return false
		}
	}

	return true
}

// verifyPassword verifies a plaintext password against a stored hash
func verifyPassword(plaintext, hash, hashType string) bool {
	switch hashType {
	case "bcrypt":
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
		return err == nil
	case "sha256":
		// Simple SHA256 hash (not recommended for production)
		hasher := sha256.New()
		hasher.Write([]byte(plaintext))
		plaintextHash := hex.EncodeToString(hasher.Sum(nil))
		return plaintextHash == hash
	default:
		slog.Warn("Unknown hash type, falling back to plaintext comparison", "hash_type", hashType)
		return plaintext == hash
	}
}
