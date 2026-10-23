package rules

import (
	"path/filepath"
	"strings"

	"github.com/pbadevel/Uplert/internal/model"
)

type ExecFromWatchDir struct {
	Dirs []string // absolute paths
}

func (ExecFromWatchDir) ID() string {
	return "exec_from_watch_dir"
}

func (r ExecFromWatchDir) Evaluate(ev model.ProcessEvent) []model.Finding {
	if ev.Exe == "" {
		return nil
	}

	exe := filepath.Clean(ev.Exe)

	for _, dir := range r.Dirs {
		dir = filepath.Clean(dir)
		if exe == dir || strings.HasPrefix(exe, dir+string(filepath.Separator)) {
			return []model.Finding{
				{
					RuleID:  r.ID(),
					Level:   model.LevelCritical,
					Message: "process executed from watched directory",
					Path:    ev.Exe,
					Time:    ev.Time,
				},
			}
		}
	}

	return nil
}

type WebSpawnedShell struct {
	WebParents map[string]bool
	ShellNames map[string]bool
}

// matchName compares a /proc comm name with the configured name.
// comm is truncated to 15 chars and often carries a version suffix
// like "php-fpm8.2", so we match on prefix with a non-letter boundary.
func matchName(actual, wanted string) bool {
	if actual == wanted {
		return true
	}

	if len(actual) > len(wanted) && strings.HasPrefix(actual, wanted) {
		next := actual[len(wanted)]

		if next >= 'a' && next <= 'z' || next >= 'A' && next <= 'Z' {
			return false
		}

		return true
	}

	return false
}

func (WebSpawnedShell) ID() string {
	return "web_spawned_shell"
}

func (r WebSpawnedShell) Evaluate(ev model.ProcessEvent) []model.Finding {
	for parent := range r.WebParents {
		if !matchName(ev.ParentName, parent) {
			continue
		}

		for shell := range r.ShellNames {
			if matchName(ev.Name, shell) {
				return []model.Finding{
					{
						RuleID:  r.ID(),
						Level:   model.LevelCritical,
						Message: "web process spawned shell/external tool",
						Path:    ev.Exe,
						Time:    ev.Time,
					},
				}
			}
		}
	}

	return nil
}
