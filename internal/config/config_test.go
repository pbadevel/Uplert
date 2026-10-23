package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "config.yaml")

	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestDefaults(t *testing.T) {
	cfg, err := Load(writeConfig(t, `
watch:
  dirs:
    - ./uploads
`))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.LogLevel != LogLevelInfo {
		t.Errorf("log level default: %s", cfg.LogLevel)
	}

	if cfg.App.Workers != 2 || cfg.App.DebounceMS != 300 {
		t.Errorf("app defaults wrong: %+v", cfg.App)
	}

	// Unset dry_run must default to true.
	if !cfg.ProcessDryRun() {
		t.Error("dry_run must default to true")
	}

	if cfg.ProcessKillOnlyCritical() != true {
		t.Error("kill_only_critical must default to true")
	}

	if cfg.ProcessEnabled() {
		t.Error("process must be disabled by default")
	}
}

func TestValidation(t *testing.T) {
	_, err := Load(writeConfig(t, `watch:
  dirs: []
`))
	if err == nil {
		t.Fatal("expected error for empty watch dirs")
	}

	_, err = Load(writeConfig(t, `
watch:
  dirs: [./uploads]
log_level: trace
`))
	if err == nil {
		t.Fatal("expected error for bad log level")
	}

	_, err = Load(writeConfig(t, `
watch:
  dirs: [./uploads]
log_format: csv
`))
	if err == nil {
		t.Fatal("expected error for bad log format")
	}
}

func TestEnvLevelOverride(t *testing.T) {
	t.Setenv("UPLERT_LOG_LEVEL", "debug")

	cfg, err := Load(writeConfig(t, `
watch:
  dirs: [./uploads]
log_level: info
`))
	if err != nil {
		t.Fatal(err)
	}

	if cfg.LogLevel != LogLevelDebug {
		t.Fatalf("env override failed: %s", cfg.LogLevel)
	}
}
