package app

import (
	"context"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/pbadevel/Uplert/internal/alert"
	"github.com/pbadevel/Uplert/internal/config"
	"github.com/pbadevel/Uplert/internal/model"
	"github.com/pbadevel/Uplert/internal/rules"
)

// fakeWatcher feeds N events, then closes the channel.
type fakeWatcher struct {
	events []model.FileEvent
}

func (f *fakeWatcher) Run(ctx context.Context, out chan<- model.FileEvent) error {
	for _, ev := range f.events {
		select {
		case out <- ev:
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

type collectingAlerter struct {
	mu       sync.Mutex
	findings []model.Finding
}

func (c *collectingAlerter) Alert(_ context.Context, f model.Finding) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.findings = append(c.findings, f)

	return nil
}

func appCfg(debounceMS int) (config.App, config.Watch) {
	return config.App{
		DebounceMS:          debounceMS,
		EventsBuffer:        16,
		Workers:             2,
		ScanIntervalSeconds: 0,
	}, config.Watch{}
}

func newTestApp(t *testing.T, dir string, alerter alert.Alerter, debounceMS int) *App {
	t.Helper()

	appCfgC, watchCfg := appCfg(debounceMS)

	reg := rules.NewRegistry(rules.DangerousExtension{
		Exts: map[string]bool{".php": true},
	})

	return New(
		testLogger(t),
		&fakeWatcher{
			events: []model.FileEvent{
				{Op: model.OpCreate, Path: filepath.Join(dir, "shell.php"), Time: time.Now()},
			},
		},
		reg,
		appCfgC,
		watchCfg,
		nil, // no process detector
		nil,
		nil, // policy only used on the process path
		alerter,
	)
}

func TestFindingReachesAlerter(t *testing.T) {
	// Regression: the alert loop must stay alive until the findings
	// channel closes (previously it exited on the first empty read).
	dir := t.TempDir()

	a := collectingAlerter{}
	ap := newTestApp(t, dir, &a, 100)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ap.Run(ctx); err != nil {
		t.Fatalf("app.Run: %v", err)
	}

	if len(a.findings) != 1 {
		t.Fatalf("expected 1 finding, got %d: %+v", len(a.findings), a.findings)
	}

	if a.findings[0].RuleID != "dangerous_extension" {
		t.Fatalf("unexpected rule: %s", a.findings[0].RuleID)
	}
}

func TestDedupSuppressesRepeats(t *testing.T) {
	dir := t.TempDir()

	a := collectingAlerter{}
	ap := newTestApp(t, dir, &a, 50)

	// Many identical findings within TTL: only the first may pass.
	f := model.Finding{
		RuleID: "dangerous_extension",
		Path:   filepath.Join(dir, "shell.php"),
		Level:  model.LevelHigh,
		Time:   time.Now(),
	}

	if reported := ap.shouldSendFinding(f); !reported {
		t.Error("first unique finding must be delivered")
	}

	for i := 0; i < 3; i++ {
		if ap.shouldSendFinding(f) {
			t.Errorf("duplicate finding %d must be suppressed", i)
		}
	}

	if len(a.findings) != 0 {
		t.Error("alerter must not be called directly in this test")
	}
}

func TestMarkUnseenAllowsRetryAfterWindow(t *testing.T) {
	dir := t.TempDir()

	a := collectingAlerter{}
	ap := newTestApp(t, dir, &a, 50)

	f := model.Finding{
		RuleID: "dangerous_extension",
		Path:   filepath.Join(dir, "shell.php"),
		Level:  model.LevelHigh,
		Time:   time.Now(),
	}

	if !ap.shouldSendFinding(f) {
		t.Fatal("first finding must be delivered")
	}

	// Still within the retry window.
	if ap.shouldSendFinding(f) {
		t.Fatal("duplicate must be suppressed before markUnseen")
	}

	ap.markUnseen(f)

	// markUnseen ages out the key, but the retry grace is ~30s, so
	// a retry far in the future must pass again.
	now31s := time.Now().Add(31 * time.Second)

	key := f.RuleID + "|" + f.Path + "|" + string(f.Level)

	if !ap.shouldSendKey(key, now31s) {
		t.Fatal("finding must be retryable after markUnseen")
	}
}
