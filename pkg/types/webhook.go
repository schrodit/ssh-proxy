package types

type WebhookAuthType string

const (
	WebhookAuthTypePassword            WebhookAuthType = "password"
	WebhookAuthTypePublicKey           WebhookAuthType = "publicKey"
	WebhookAuthTypeKeyboardInteractive WebhookAuthType = "keyboardInteractive"
)

// WebhookAuthRequest is the shared base JSON body sent to webhook endpoints.
type WebhookAuthRequest struct {
	Username string          `json:"username"`
	AuthType WebhookAuthType `json:"authType"`
}

// WebhookPasswordAuthRequest is sent for password authentication.
type WebhookPasswordAuthRequest struct {
	WebhookAuthRequest
	Password string `json:"password"`
}

// WebhookPublicKeyAuthRequest is sent for public key authentication.
type WebhookPublicKeyAuthRequest struct {
	WebhookAuthRequest
	PublicKey string `json:"publicKey"`
}

// WebhookKeyboardInteractiveAuthRequest is sent for keyboard-interactive
// authentication challenge rounds.
type WebhookKeyboardInteractiveAuthRequest struct {
	WebhookAuthRequest
	SessionID      string   `json:"sessionId"`
	ChallengeRound int      `json:"challengeRound"`
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
