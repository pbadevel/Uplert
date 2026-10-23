package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/pbadevel/Uplert/internal/model"
)

// Webhook POSTs findings as JSON to a user-provided URL. Works with
// Discord/Slack-compatible relays, n8n, serverless functions, etc.
type Webhook struct {
	url     string
	timeout time.Duration
	client  *http.Client
}

func NewWebhook(url string, timeout time.Duration) *Webhook {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	return &Webhook{
		url:     url,
		timeout: timeout,
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

func (w *Webhook) Alert(ctx context.Context, f model.Finding) error {
	ctx, cancel := context.WithTimeout(ctx, w.timeout)
	defer cancel()

	body, err := json.Marshal(map[string]any{
		"source":  "uplert",
		"rule":    f.RuleID,
		"level":   string(f.Level),
		"message": f.Message,
		"path":    f.Path,
		"time":    f.Time.Format(time.RFC3339),
	})
	if err != nil {
		return fmt.Errorf("marshal finding: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("create webhook request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "uplert")

	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("webhook request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}
