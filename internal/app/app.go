package app

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pbadevel/Uplert/internal/alert"
	"github.com/pbadevel/Uplert/internal/config"
	"github.com/pbadevel/Uplert/internal/model"
	"github.com/pbadevel/Uplert/internal/process"
	"github.com/pbadevel/Uplert/internal/rules"
	"github.com/pbadevel/Uplert/internal/watcher"
)

type App struct {
	log      *slog.Logger
	watcher  watcher.Watcher
	rules    *rules.Registry
	alerters []alert.Alerter

	eventsBuffer int
	workers      int
	debounce     time.Duration
	scanInterval time.Duration
	scanOnStart  bool

	dirs   []string
	ignore []string

	processDetector process.ProcessDetector
	processRules    *rules.ProcessRegistry
	policy          *process.Policy

	seenMu       sync.Mutex
	seenFindings map[string]time.Time
	findingTTL   time.Duration
}

func New(
	log *slog.Logger,
	w watcher.Watcher,
	registry *rules.Registry,
	appCfg config.App,
	watchCfg config.Watch,
	pd process.ProcessDetector,
	pr *rules.ProcessRegistry,
	pol *process.Policy,
	alerters ...alert.Alerter,
) *App {
	if appCfg.EventsBuffer <= 0 {
		appCfg.EventsBuffer = 4096
	}

	if appCfg.Workers <= 0 {
		appCfg.Workers = 2
	}

	if appCfg.DebounceMS <= 0 {
		appCfg.DebounceMS = 300
	}

	if appCfg.ScanIntervalSeconds < 0 {
		appCfg.ScanIntervalSeconds = 0
	}

	return &App{
		log:             log,
		watcher:         w,
		rules:           registry,
		alerters:        alerters,
		eventsBuffer:    appCfg.EventsBuffer,
		workers:         appCfg.Workers,
		debounce:        time.Duration(appCfg.DebounceMS) * time.Millisecond,
		scanInterval:    time.Duration(appCfg.ScanIntervalSeconds) * time.Second,
		scanOnStart:     appCfg.ScanOnStart,
		dirs:            watchCfg.Dirs,
		ignore:          watchCfg.Ignore,
		processDetector: pd,
		processRules:    pr,
		policy:          pol,
		seenFindings:    make(map[string]time.Time),
		findingTTL:      10 * time.Minute,
	}
}

func (a *App) Run(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	raw := make(chan model.FileEvent, a.eventsBuffer)
	jobs := make(chan model.FileEvent, a.eventsBuffer)
	findings := make(chan model.Finding, a.eventsBuffer)
	errCh := make(chan error, 3)

	var workersWG sync.WaitGroup
	var allWG sync.WaitGroup

	// Filesystem watcher.
	allWG.Add(1)
	go func() {
		defer allWG.Done()

		if err := a.watcher.Run(ctx, raw); err != nil && ctx.Err() == nil {
			select {
			case errCh <- fmt.Errorf("watcher failed: %w", err):
			default:
			}
		}
	}()

	// Process detector.
	if a.processDetector != nil && a.processRules != nil && a.policy != nil {
		procEvents := make(chan model.ProcessEvent, a.eventsBuffer)

		allWG.Add(1)
		go func() {
			defer allWG.Done()
			defer close(procEvents)
			if err := a.processDetector.Run(ctx, procEvents); err != nil && ctx.Err() == nil {
				select {
				case errCh <- fmt.Errorf("process detector failed: %w", err):
				default:
				}
			}
		}()

		allWG.Add(1)
		go func() {
			defer allWG.Done()
			a.processWorkerLoop(ctx, procEvents, findings)
		}()
	}

	// Fallback periodic scanner.
	if a.scanOnStart || a.scanInterval > 0 {
		allWG.Add(1)
		go func() {
			defer allWG.Done()
			a.scanLoop(ctx, raw)
		}()
	}

	// Debouncer: coalesces repeated events for the same path.
	allWG.Add(1)
	go func() {
		defer allWG.Done()
		a.debounceLoop(ctx, raw, jobs)
		close(jobs)
	}()

	// Worker pool: evaluates rules in parallel.
	for i := 0; i < a.workers; i++ {
		workersWG.Add(1)
		go func() {
			defer workersWG.Done()
			a.workerLoop(ctx, jobs, findings)
		}()
	}

	// Close findings channel after all workers are done.
	go func() {
		workersWG.Wait()
		close(findings)
	}()

	// Alerter loop.
	allWG.Add(1)
	go func() {
		defer allWG.Done()
		a.alertLoop(ctx, findings)
	}()

	select {
	case <-ctx.Done():
	case err := <-errCh:
		cancel()
		allWG.Wait()
		return err
	}

	cancel()
	allWG.Wait()

	return nil
}

func (a *App) workerLoop(
	ctx context.Context,
	jobs <-chan model.FileEvent,
	findings chan<- model.Finding,
) {
	for {
		select {
		case <-ctx.Done():
			return

		case ev, ok := <-jobs:
			if !ok {
				return
			}

			a.log.Debug("processing job",
				"op", ev.Op,
				"path", ev.Path,
			)

			for _, finding := range a.rules.Evaluate(ev) {
				select {
				case findings <- finding:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

// alertLoop consumes findings until the channel is closed or the
// context is cancelled. Note: there must be no default branch here,
// otherwise the loop exits immediately on startup and the whole
// alerting pipeline dies (previously observed regression).
func (a *App) alertLoop(ctx context.Context, findings <-chan model.Finding) {
	for {
		select {
		case <-ctx.Done():
			return

		case f, ok := <-findings:
			if !ok {
				return
			}

			if !a.shouldSendFinding(f) {
				continue
			}

			a.dispatch(ctx, f)
		}
	}
}

func (a *App) dispatch(ctx context.Context, f model.Finding) {
	var failed bool

	for _, alerter := range a.alerters {
		if err := alerter.Alert(ctx, f); err != nil {
			failed = true

			a.log.Error("alert failed",
				"rule", f.RuleID,
				"path", f.Path,
				"error", err,
			)
		}
	}

	if failed {
		// At least one alerter failed: allow a retry later instead of
		// silencing this finding for the whole TTL.
		a.markUnseen(f)
	}
}

type pendingEntry struct {
	ops  map[model.Op]struct{}
	last time.Time
}

func (a *App) debounceLoop(
	ctx context.Context,
	raw <-chan model.FileEvent,
	jobs chan<- model.FileEvent,
) {
	pending := make(map[string]*pendingEntry)

	interval := a.debounce / 2
	if interval < 50*time.Millisecond {
		interval = 50 * time.Millisecond
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			a.flushAll(ctx, pending, jobs)
			return

		case ev, ok := <-raw:
			if !ok {
				a.flushAll(ctx, pending, jobs)
				return
			}

			a.addPending(pending, ev)

		case <-ticker.C:
			a.flushExpired(ctx, pending, jobs)
		}
	}
}

func (a *App) addPending(pending map[string]*pendingEntry, ev model.FileEvent) {
	if ev.IsDir {
		return
	}

	path := filepath.Clean(ev.Path)

	// If file was removed, drop pending state.
	// Current rules mostly ignore remove events anyway.
	if ev.Op == model.OpRemove {
		delete(pending, path)
		return
	}

	entry, ok := pending[path]
	if !ok {
		entry = &pendingEntry{
			ops: make(map[model.Op]struct{}),
		}
		pending[path] = entry
	}

	entry.ops[ev.Op] = struct{}{}
	entry.last = time.Now()
}

func (a *App) flushExpired(
	ctx context.Context,
	pending map[string]*pendingEntry,
	jobs chan<- model.FileEvent,
) {
	now := time.Now()

	var expired []string

	for path, entry := range pending {
		if now.Sub(entry.last) >= a.debounce {
			expired = append(expired, path)
		}
	}

	for _, path := range expired {
		entry := pending[path]
		if !a.emitEntry(ctx, path, entry, jobs) {
			return
		}
		delete(pending, path)
	}
}

func (a *App) flushAll(
	ctx context.Context,
	pending map[string]*pendingEntry,
	jobs chan<- model.FileEvent,
) {
	for path, entry := range pending {
		if !a.emitEntry(ctx, path, entry, jobs) {
			return
		}
		delete(pending, path)
	}
}

func (a *App) emitEntry(
	ctx context.Context,
	path string,
	entry *pendingEntry,
	jobs chan<- model.FileEvent,
) bool {
	// Emit in a predictable order.
	order := []model.Op{
		model.OpCreate,
		model.OpRename,
		model.OpWrite,
		model.OpChmod,
		model.OpScan,
	}

	for _, op := range order {
		if _, ok := entry.ops[op]; !ok {
			continue
		}

		ev := model.FileEvent{
			Op:    op,
			Path:  path,
			IsDir: false,
			Time:  entry.last,
		}

		if !sendEvent(ctx, jobs, ev) {
			return false
		}
	}

	return true
}

func sendEvent(
	ctx context.Context,
	ch chan<- model.FileEvent,
	ev model.FileEvent,
) bool {
	select {
	case ch <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

func (a *App) scanLoop(ctx context.Context, out chan<- model.FileEvent) {
	if a.scanOnStart {
		a.log.Debug("fallback scan started", "reason", "startup")
		a.scanOnce(ctx, out)
	}

	if a.scanInterval <= 0 {
		return
	}

	ticker := time.NewTicker(a.scanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-ticker.C:
			a.log.Debug("fallback scan started", "reason", "interval")
			a.scanOnce(ctx, out)
		}
	}
}

func (a *App) scanOnce(ctx context.Context, out chan<- model.FileEvent) {
	for _, dir := range a.dirs {
		dir = filepath.Clean(dir)

		info, err := os.Stat(dir)
		if err != nil {
			a.log.Debug("fallback scan skipped dir",
				"dir", dir,
				"error", err,
			)
			continue
		}

		if !info.IsDir() {
			continue
		}

		err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			if d.IsDir() {
				return nil
			}

			path = filepath.Clean(path)

			if a.isIgnored(path) {
				return nil
			}

			ev := model.FileEvent{
				Op:    model.OpScan,
				Path:  path,
				IsDir: false,
				Time:  time.Now(),
			}

			select {
			case out <- ev:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})

		if err != nil {
			if ctx.Err() != nil {
				return
			}

			a.log.Debug("fallback scan aborted dir",
				"dir", dir,
				"error", err,
			)
		}
	}
}

func (a *App) isIgnored(path string) bool {
	path = filepath.Clean(path)

	for _, ignore := range a.ignore {
		ignore = filepath.Clean(ignore)

		if path == ignore {
			return true
		}

		if strings.HasPrefix(path, ignore+string(os.PathSeparator)) {
			return true
		}
	}

	return false
}

func (a *App) processWorkerLoop(
	ctx context.Context,
	procEvents <-chan model.ProcessEvent,
	findings chan<- model.Finding,
) {
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-procEvents:
			if !ok {
				return
			}

			a.log.Debug("process event",
				"pid", ev.Pid,
				"name", ev.Name,
				"exe", ev.Exe,
				"parent", ev.ParentName,
			)

			for _, f := range a.processRules.Evaluate(ev) {
				// Dedup BEFORE deciding on a kill: repeated scans see the
				// same long-running process every interval.
				key := fmt.Sprintf("%s|%d|%s", f.RuleID, ev.Pid, f.Level)

				if !a.shouldSendKey(key, ev.Time) {
					continue
				}

				far := f
				far.Time = ev.Time

				alert, action := a.policy.Decide(f)

				if action != process.ActionNone {
					go func(pid int32, finding model.Finding, act process.Action) {
						if msg := a.policy.Execute(act, finding, pid); msg != "" {
							a.log.Info("response action", "detail", msg)
						}
					}(ev.Pid, far, action)
				}

				if !alert {
					continue
				}

				select {
				case findings <- far:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (a *App) shouldSendFinding(f model.Finding) bool {
	key := fmt.Sprintf("%s|%s|%s", f.RuleID, f.Path, f.Level)
	return a.shouldSendKey(key, time.Now())
}

func (a *App) shouldSendKey(key string, now time.Time) bool {
	a.seenMu.Lock()
	defer a.seenMu.Unlock()

	if sentAt, ok := a.seenFindings[key]; ok {
		if now.Sub(sentAt) < a.findingTTL {
			return false
		}
	}

	a.seenFindings[key] = now

	if len(a.seenFindings) > 50000 {
		for k, v := range a.seenFindings {
			if now.Sub(v) > a.findingTTL {
				delete(a.seenFindings, k)
			}
		}
	}

	return true
}

// markUnseen allows the same finding to be delivered again after a
// short pause, used when alert delivery failed.
func (a *App) markUnseen(f model.Finding) {
	key := fmt.Sprintf("%s|%s|%s", f.RuleID, f.Path, f.Level)

	a.seenMu.Lock()
	defer a.seenMu.Unlock()

	a.seenFindings[key] = time.Now().Add(-a.findingTTL + 30*time.Second)
}

// ScanOnce runs the rules over the configured directories and returns
// the findings. Used by the one-shot CLI scan mode.
func (a *App) ScanOnce(ctx context.Context) []model.Finding {
	var findings []model.Finding

	for _, dir := range a.dirs {
		dir = filepath.Clean(dir)

		info, err := os.Stat(dir)
		if err != nil {
			continue
		}

		if !info.IsDir() {
			continue
		}

		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			if d.IsDir() {
				return nil
			}

			path = filepath.Clean(path)

			if a.isIgnored(path) {
				return nil
			}

			findings = append(findings, a.rules.Evaluate(model.FileEvent{
				Op:   model.OpScan,
				Path: path,
				Time: time.Now(),
			})...)

			return nil
		})
	}

	return findings
}
