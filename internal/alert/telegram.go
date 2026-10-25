package alert

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"strings"
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
	// Telegram carries actionable alerts only: medium and above.
	if f.Level == model.LevelInfo {
		return nil
	}

	apiURL := fmt.Sprintf(
		"https://api.telegram.org/bot%s/sendMessage",
		url.PathEscape(t.token),
	)

	payload, err := json.Marshal(map[string]any{
		"chat_id":    t.chatID,
		"text":       formatTelegram(f),
		"parse_mode": "HTML",
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

// formatTelegram renders a compact HTML alert card.
func formatTelegram(f model.Finding) string {
	// Icon + level text per severity.
	head, level := "🟡 ", "MEDIUM"

	switch f.Level {
	case model.LevelCritical:
		head, level = "🔴 ", "CRITICAL"
	case model.LevelHigh:
		head, level = "🟠 ", "HIGH"
	case model.LevelInfo:
		head, level = "⚪ ", "info"
	}

	var b strings.Builder

	fmt.Fprintf(&b, "%s<b>uplert alert</b> · %s\n", head, level)
	fmt.Fprintf(&b, "<code>%s</code>\n", html.EscapeString(f.RuleID))
	fmt.Fprintf(&b, "%s\n", html.EscapeString(f.Message))

	if f.Path != "" {
		fmt.Fprintf(&b, "📁 <code>%s</code>\n",
			html.EscapeString(shortPath(f.Path)))
	}

	fmt.Fprintf(&b, "🕒 %s", f.Time.Format("02 Jan 15:04:05"))
	return b.String()
}

// shortPath trims very long paths to keep the message readable.
func shortPath(path string) string {
	const max = 96

	if len(path) <= max {
		return path
	}

	return "…" + path[len(path)-max:]
}
