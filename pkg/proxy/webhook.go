package proxy

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/schrodit/ssh-proxy/pkg/config"
	"github.com/schrodit/ssh-proxy/pkg/types"
)

const (
	// defaultWebhookTimeout is the default timeout for webhook HTTP requests.
	defaultWebhookTimeout = 5 * time.Second
)

// callWebhookAuth sends a POST request to the configured webhook to authenticate a user.
// The webhook returns 200 if the user is authorized and 401 if unauthorized.
func callWebhookAuth(cfg *config.WebhookConfig, req any) (bool, error) {
	r, err := newWebhookRequest(cfg, req)
	if err != nil {
		return false, err
	}

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

func callKeyboardInteractiveWebhook(cfg *config.WebhookConfig, req *types.WebhookKeyboardInteractiveAuthRequest) (*types.WebhookKeyboardInteractiveResponse, bool, error) {
	r, err := newWebhookRequest(cfg, req)
	if err != nil {
		return nil, false, err
	}

	slog.Debug("Calling keyboard-interactive webhook", "url", cfg.URL, "username", req.Username, "challenge_round", req.ChallengeRound)

	resp, err := r.Post(cfg.URL)
	if err != nil {
		return nil, false, fmt.Errorf("keyboard-interactive webhook request failed: %w", err)
	}

	switch resp.StatusCode() {
	case http.StatusOK:
		return nil, true, nil
	case http.StatusUnauthorized:
		return nil, false, nil
	case http.StatusAccepted:
		var challenge types.WebhookKeyboardInteractiveResponse
		if len(resp.Body()) == 0 {
			return nil, false, fmt.Errorf("keyboard-interactive webhook returned %d without a challenge body", resp.StatusCode())
		}
		if err := json.Unmarshal(resp.Body(), &challenge); err != nil {
			return nil, false, fmt.Errorf("failed to decode keyboard-interactive webhook response: %w", err)
		}
		return &challenge, false, nil
	default:
		return nil, false, fmt.Errorf("keyboard-interactive webhook returned unexpected status %d: %s", resp.StatusCode(), resp.String())
	}
}

func newWebhookRequest(cfg *config.WebhookConfig, body any) (*resty.Request, error) {
	timeout := defaultWebhookTimeout
	if cfg.Timeout != "" {
		d, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid webhook timeout %q: %w", cfg.Timeout, err)
		}
		timeout = d
	}

	client := resty.New().SetTimeout(timeout)
	r := client.R().
		SetHeader("Content-Type", "application/json").
		SetBody(body)

	for k, v := range cfg.Headers {
		r.SetHeader(k, v)
	}

	return r, nil
}
