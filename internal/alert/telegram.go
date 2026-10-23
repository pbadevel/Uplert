package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/pbadevel/Uplert/internal/model"
)

// Telegram sends findings as plain-text messages via the Telegram
// Bot API. token/chat come from the config.
type Telegram struct {
	token  string
	chatID string
	client *http.Client
}

func NewTelegram(token, chatID string) *Telegram {
	return &Telegram{
		token:  token,
		chatID: chatID,
		client: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (t *Telegram) Alert(ctx context.Context, f model.Finding) error {
	apiURL := fmt.Sprintf(
		"https://api.telegram.org/bot%s/sendMessage",
		url.PathEscape(t.token),
	)

	payload, err := json.Marshal(map[string]any{
		"chat_id": t.chatID,
		"text": fmt.Sprintf(
			"[uplert] %s %s\nrule: %s\npath: %s\n%s",
			f.Level, f.Time.Format("15:04:05"), f.RuleID, f.Path, f.Message,
		),
		"disable_notification": f.Level != model.LevelCritical &&
			f.Level != model.LevelHigh,
	})
	if err != nil {
		return fmt.Errorf("marshal telegram payload: %w", err)
	}

	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost, apiURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create telegram request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("telegram request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))

		return fmt.Errorf(
			"telegram returned status %d: %s",
			resp.StatusCode, string(body))
	}

	return nil
}
