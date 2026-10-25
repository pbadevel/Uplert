package process

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/pbadevel/Uplert/internal/model"
	gops "github.com/shirou/gopsutil/v4/process"
)

type ProcessDetector interface {
	Run(ctx context.Context, events chan<- model.ProcessEvent) error
}

type Detector struct {
	log        *slog.Logger
	WatchDirs  []string // absolute
	WebParents map[string]bool
	ShellNames map[string]bool
	Interval   time.Duration

	mu       sync.Mutex
	seenPids map[int32]time.Time
	pidTTL   time.Duration
}

func NewDetector(log *slog.Logger, watchDirs []string, webParents, shellNames []string, intervalSeconds int) *Detector {
	if intervalSeconds <= 0 {
		intervalSeconds = 2
	}

	abs := make([]string, 0, len(watchDirs))
	for _, d := range watchDirs {
		a, err := filepath.EvalSymlinks(d)
		if err != nil {
			a, _ = filepath.Abs(d)
		}

		abs = append(abs, filepath.Clean(a))
	}

	return &Detector{
		log:        log,
		WatchDirs:  abs,
		WebParents: toSet(webParents),
		ShellNames: toSet(shellNames),
		Interval:   time.Duration(intervalSeconds) * time.Second,
		seenPids:   make(map[int32]time.Time),
		pidTTL:     10 * time.Minute,
	}
}

func (d *Detector) Run(ctx context.Context, events chan<- model.ProcessEvent) error {
	// Scan immediately, then on interval.
	d.scan(ctx, events)

	ticker := time.NewTicker(d.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			d.reapExpired()
			d.scan(ctx, events)
		}
	}
}

func (d *Detector) scan(ctx context.Context, events chan<- model.ProcessEvent) {
	procs, err := gops.Processes()
	if err != nil {
		d.log.Debug("process scan failed", "error", err)
		return
	}

	now := time.Now()

	for _, p := range procs {
		if d.isSelfOrParent(p.Pid) {
			continue
		}

		name, err := p.Name()
		if err != nil {
			continue
		}

		exe, _ := p.Exe()

		parentName := ""
		var parentPid int32
		if parent, err := p.Parent(); err == nil && parent != nil {
			parentPid = parent.Pid
			parentName, _ = parent.Name()
		}

		// Candidate 1: binary inside a watch dir.
		// Candidate 2: child of a web process.
		// Candidate 3: working directory inside a watch dir — covers
		// uploaded scripts run via a system interpreter (/bin/sh,
		// python3), where exe points outside the uploads.

		cwd, _ := p.Cwd()

		isCandidate := d.exeInWatchDir(exe) ||
			d.WebParents[parentName] ||
			d.cwdInWatchDir(cwd)

		if isCandidate {
			if !d.markSeen(p.Pid, now) {
				continue // already reported recently
			}

			if !send(ctx, events, model.ProcessEvent{
				Pid: p.Pid, Name: name, Exe: exe,
				Cwd:       cwd,
				ParentPid: parentPid, ParentName: parentName,
				Time: now,
			}) {
				return
			}
		}
	}
}

func (d *Detector) markSeen(pid int32, now time.Time) bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if sentAt, ok := d.seenPids[pid]; ok {
		if now.Sub(sentAt) < d.pidTTL {
			return false
		}
	}

	d.seenPids[pid] = now

	// Opportunistic cleanup.
	if len(d.seenPids) > 50000 {
		for k, v := range d.seenPids {
			if now.Sub(v) > d.pidTTL {
				delete(d.seenPids, k)
			}
		}
	}

	return true
}

func (d *Detector) reapExpired() {
	cutoff := time.Now().Add(-d.pidTTL)

	d.mu.Lock()
	defer d.mu.Unlock()

	for pid, seen := range d.seenPids {
		if seen.Before(cutoff) {
			delete(d.seenPids, pid)
		}
	}
}

// isSelfOrParent avoids flagging (or killing) uplert itself and its
// direct parent, which is typically the shell/systemd running it.
func (d *Detector) isSelfOrParent(pid int32) bool {
	self := int32(os.Getpid())

	if pid == self {
		return true
	}

	if parent, err := gops.NewProcess(self); err == nil && parent != nil {
		if pp, err := parent.Parent(); err == nil && pp != nil {
			return pid == pp.Pid
		}
	}

	return false
}

func (d *Detector) exeInWatchDir(exe string) bool {
	if exe == "" {
		return false
	}

	exe = filepath.Clean(exe)

	for _, dir := range d.WatchDirs {
		if exe == dir || strings.HasPrefix(exe, dir+string(filepath.Separator)) {
			return true
		}
	}

	return false
}

func (d *Detector) cwdInWatchDir(cwd string) bool {
	return d.exeInWatchDir(cwd) // same prefix logic
}

func send(ctx context.Context, ch chan<- model.ProcessEvent, ev model.ProcessEvent) bool {
	select {
	case ch <- ev:
		return true
	case <-ctx.Done():
		return false
	}
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}
	return m
}
