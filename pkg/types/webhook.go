package types

// WebhookAuthRequest is the shared base JSON body sent to webhook endpoints.
type WebhookAuthRequest struct {
	Username string `json:"username"`
	AuthType string `json:"auth_type"` // "password", "public_key", or "keyboard_interactive"
}

// WebhookPasswordAuthRequest is sent for password authentication.
type WebhookPasswordAuthRequest struct {
	WebhookAuthRequest
	Password string `json:"password"`
}

// WebhookPublicKeyAuthRequest is sent for public key authentication.
type WebhookPublicKeyAuthRequest struct {
	WebhookAuthRequest
	PublicKey string `json:"public_key"`
}

// WebhookKeyboardInteractiveAuthRequest is sent for keyboard-interactive
// authentication challenge rounds.
type WebhookKeyboardInteractiveAuthRequest struct {
	WebhookAuthRequest
	SessionID      string   `json:"session_id"`
	ChallengeRound int      `json:"challenge_round"`
	Answers        []string `json:"answers,omitempty"`
}

// WebhookKeyboardInteractiveResponse describes the next challenge round that
// should be presented to the SSH client. A 202 response should include this
// payload, while 200 means authentication succeeded and 401 means denied.
type WebhookKeyboardInteractiveResponse struct {
	Name        string   `json:"name,omitempty"`
	Instruction string   `json:"instruction,omitempty"`
	Questions   []string `json:"questions"`
	Echos       []bool   `json:"echos,omitempty"`
}
