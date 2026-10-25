package process

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
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
			killChildren(pid) // script may have spawned helpers
			return nil
		}

		time.Sleep(100 * time.Millisecond)
	}

	killChildren(pid)

	if err := syscall.Kill(int(pid), syscall.SIGKILL); err != nil {
		return fmt.Errorf("send SIGKILL to %d: %w", pid, err)
	}

	return nil
}

// killChildren terminates child processes that the target spawned.
// Killing only the parent would leave, say, a php runner writing
// malicious files in a loop.
func killChildren(pid int32) {
	kids := childPids(pid)

	for _, kid := range kids {
		// Never touch our own process group.
		if sysPgid(kid) == syscall.Getpgrp() {
			_ = syscall.Kill(int(kid), syscall.SIGTERM)
			continue
		}

		_ = syscall.Kill(int(kid), syscall.SIGKILL)
	}
}

// childPids lists direct children by scanning ppid in /proc.
func childPids(parent int32) []int32 {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	var out []int32

	for _, e := range entries {
		raw := e.Name()

		pid, err := strconv.Atoi(raw)
		if err != nil {
			continue
		}

		data, err := os.ReadFile("/proc/" + raw + "/stat")
		if err != nil {
			continue
		}

		// stat: pid (comm) state ppid ...
		open := strings.LastIndex(string(data), ")")

		fields := strings.Fields(string(data)[open+2:])
		if len(fields) < 2 {
			continue
		}

		ppid, err := strconv.Atoi(fields[1])
		if err == nil && ppid == int(parent) {
			out = append(out, int32(pid))
		}
	}

	return out
}

func sysPgid(pid int32) int {
	g, err := syscall.Getpgid(int(pid))
	if err != nil {
		return 0
	}

	return g
}
