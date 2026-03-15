package types

// WebhookAuthRequest is the JSON body sent to the webhook endpoint.
type WebhookAuthRequest struct {
	Username  string `json:"username"`
	AuthType  string `json:"auth_type"` // "password" or "public_key"
	Password  string `json:"password,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}
