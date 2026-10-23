package process

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/pbadevel/Uplert/internal/model"
)

type Action string

const (
	ActionNone  Action = "none"
	ActionAlert Action = "alert"
	ActionKill  Action = "kill"
)

type Policy struct {
	Enabled          bool
	DryRun           bool
	KillOnlyCritical bool
}

func DefaultPolicy() *Policy {
	return &Policy{
		Enabled:          false,
		DryRun:           true,
		KillOnlyCritical: true,
	}
}

func (p *Policy) Decide(f model.Finding) (alert bool, action Action) {
	if f.Level != model.LevelInfo {
		alert = true
	}

	if !p.Enabled {
		return alert, ActionNone
	}

	if p.KillOnlyCritical && f.Level != model.LevelCritical {
		return alert, ActionNone
	}

	return alert, ActionKill
}

func (p *Policy) Execute(action Action, f model.Finding, pid int32) string {
	if action != ActionKill {
		return ""
	}

	if p.DryRun {
		return fmt.Sprintf(
			"DRY-RUN would kill pid=%d rule=%s path=%s",
			pid,
			f.RuleID,
			f.Path,
		)
	}

	if err := KillProcess(pid); err != nil {
		return fmt.Sprintf(
			"kill failed pid=%d rule=%s error=%v",
			pid,
			f.RuleID,
			err,
		)
	}

	return fmt.Sprintf(
		"killed pid=%d rule=%s path=%s",
		pid,
		f.RuleID,
		f.Path,
	)
}

func isAlive(pid int32) bool {
	if pid <= 0 {
		return false
	}

	err := syscall.Kill(int(pid), 0)
	if err == nil {
		return true
	}

	// EPERM/EACCES означают, что процесс существует, но нет права его трогать.
	return errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.EACCES)
}

func KillProcess(pid int32) error {
	if pid <= 1 {
		return fmt.Errorf("refuse to kill protected pid %d", pid)
	}

	if int(pid) == os.Getpid() {
		return fmt.Errorf("refuse to kill self pid %d", pid)
	}

	if !isAlive(pid) {
		return fmt.Errorf("process %d is not alive", pid)
	}

	if err := syscall.Kill(int(pid), syscall.SIGTERM); err != nil {
		return fmt.Errorf("send SIGTERM to %d: %w", pid, err)
	}

	deadline := time.Now().Add(3 * time.Second)

	for time.Now().Before(deadline) {
		if !isAlive(pid) {
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		return fmt.Errorf("send SIGKILL to %d: %w", pid, err)
	}

	return nil
}
