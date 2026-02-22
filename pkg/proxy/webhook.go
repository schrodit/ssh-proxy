package proxy

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/schrodit/ssh-proxy/pkg/config"
)

const (
	// defaultWebhookTimeout is the default timeout for webhook HTTP requests.
	defaultWebhookTimeout = 5 * time.Second
)

// WebhookAuthRequest is the JSON body sent to the webhook endpoint.
type WebhookAuthRequest struct {
	Username  string `json:"username"`
	AuthType  string `json:"auth_type"` // "password" or "public_key"
	Password  string `json:"password,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
}

// callWebhookAuth sends a POST request to the configured webhook to authenticate a user.
// The webhook returns 200 if the user is authorized and 401 if unauthorized.
func callWebhookAuth(cfg *config.WebhookConfig, req *WebhookAuthRequest) (bool, error) {
	timeout := defaultWebhookTimeout
	if cfg.Timeout != "" {
		d, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return false, fmt.Errorf("invalid webhook timeout %q: %w", cfg.Timeout, err)
		}
		timeout = d
	}

	client := resty.New().SetTimeout(timeout)

	r := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(req)

	for k, v := range cfg.Headers {
		r.SetHeader(k, v)
	}

	slog.Debug("Calling auth webhook", "url", cfg.URL, "username", req.Username, "auth_type", req.AuthType)

	resp, err := r.Post(cfg.URL)
	if err != nil {
		return false, fmt.Errorf("webhook request failed: %w", err)
	}

	switch resp.StatusCode() {
	case http.StatusOK:
		return true, nil
	case http.StatusUnauthorized:
		return false, nil
	default:
		return false, fmt.Errorf("webhook returned unexpected status %d: %s", resp.StatusCode(), resp.String())
	}
}
