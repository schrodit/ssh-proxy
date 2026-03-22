package proxy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"

	"github.com/schrodit/ssh-proxy/pkg/config"
	"github.com/schrodit/ssh-proxy/pkg/types"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

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

func (p *SSHProxy) handlePasswordAuth(conn ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
	username := conn.User()
	match := p.configManager.FindRoute(username)
	slog.Debug("Password auth attempt", "username", username)
	if match == nil {
		return nil, fmt.Errorf("user not found")
	}
	route := match.Route

	for _, authMethod := range route.Auth {
		if authMethod.Type == config.AuthMethodTypeExternalAuth && authMethod.ExternalAuth != nil {
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

		if authMethod.Type != config.AuthMethodTypePassword {
			continue
		}

		passwordToVerify := authMethod.Password
		if authMethod.PasswordHash != "" {
			passwordToVerify = authMethod.PasswordHash
		}
		if passwordToVerify == "" {
			continue
		}

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

	for _, authMethod := range route.Auth {
		if authMethod.Type == config.AuthMethodTypeExternalAuth && authMethod.ExternalAuth != nil {
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

		if authMethod.Type != config.AuthMethodTypeKey {
			continue
		}

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
		if authMethod.Type != config.AuthMethodTypeExternalAuth || authMethod.ExternalAuth == nil {
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

func comparePublicKeys(providedKey ssh.PublicKey, authorizedKeyStr string) bool {
	authorizedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKeyStr))
	if err != nil {
		slog.Error("Failed to parse authorized key", "error", err)
		return false
	}

	if providedKey.Type() != authorizedKey.Type() {
		return false
	}

	providedKeyData := providedKey.Marshal()
	authorizedKeyData := authorizedKey.Marshal()
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

func verifyPassword(plaintext, hash string, hashType config.PasswordHashType) bool {
	switch hashType {
	case config.PasswordHashTypeBcrypt:
		err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext))
		return err == nil
	case config.PasswordHashTypeSHA256:
		hasher := sha256.New()
		hasher.Write([]byte(plaintext))
		plaintextHash := hex.EncodeToString(hasher.Sum(nil))
		return plaintextHash == hash
	default:
		slog.Warn("Unknown hash type, falling back to plaintext comparison", "hash_type", hashType)
		return plaintext == hash
	}
}
