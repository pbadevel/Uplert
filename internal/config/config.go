package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelError LogLevel = "error"
)

type LogFormat string

const (
	LogFormatText LogFormat = "text"
	LogFormatJSON LogFormat = "json"
)

type Config struct {
	App       App       `yaml:"app"`
	Process   Process   `yaml:"process"`
	LogLevel  LogLevel  `yaml:"log_level"`
	LogFormat LogFormat `yaml:"log_format"`
	Watch     Watch     `yaml:"watch"`
	Alerts    Alerts    `yaml:"alerts"`
}

type App struct {
	EventsBuffer        int  `yaml:"events_buffer"`
	Workers             int  `yaml:"workers"`
	DebounceMS          int  `yaml:"debounce_ms"`
	ScanIntervalSeconds int  `yaml:"scan_interval_seconds"`
	ScanOnStart         bool `yaml:"scan_on_start"`
}

type Process struct {
	// Enabled uses a pointer to distinguish unset from false.
	Enabled *bool `yaml:"enabled"`
	// DryRun default is true: a monitor must never silently kill
	// processes unless explicitly asked to.
	DryRun *bool `yaml:"dry_run"`
	// KillOnlyCritical default is true.
	KillOnlyCritical *bool `yaml:"kill_only_critical"`

	IntervalSeconds int      `yaml:"interval_seconds"`
	WebParents      []string `yaml:"web_parents"`
	ShellNames      []string `yaml:"shell_names"`
}

type Watch struct {
	Dirs   []string `yaml:"dirs"`
	Ignore []string `yaml:"ignore"`
}

type Alerts struct {
	Stdout      bool   `yaml:"stdout"`
	Webhook     string `yaml:"webhook"`
	Telegram    string `yaml:"telegram_bot_token"`
	TelegramCID string `yaml:"telegram_chat_id"`
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if lvl := os.Getenv("UPLERT_LOG_LEVEL"); lvl != "" {
		cfg.LogLevel = LogLevel(strings.ToLower(lvl))
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	applyDefaults(&cfg)

	return &cfg, nil
}

func (c *Config) validate() error {
	switch c.LogLevel {
	case LogLevelDebug, LogLevelInfo, LogLevelError, "":
	default:
		return fmt.Errorf("unknown log_level %q (debug|info|error)", c.LogLevel)
	}

	switch c.LogFormat {
	case LogFormatText, LogFormatJSON, "":
	default:
		return fmt.Errorf("unknown log_format %q (text|json)", c.LogFormat)
	}

	if len(c.Watch.Dirs) == 0 {
		return fmt.Errorf("watch.dirs is required (at least one directory)")
	}

	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.LogLevel == "" {
		cfg.LogLevel = LogLevelInfo
	}

	if cfg.LogFormat == "" {
		cfg.LogFormat = LogFormatText
	}

	if cfg.App.EventsBuffer <= 0 {
		cfg.App.EventsBuffer = 4096
	}

	if cfg.App.Workers <= 0 {
		cfg.App.Workers = 2
	}

	if cfg.App.DebounceMS <= 0 {
		cfg.App.DebounceMS = 300
	}

	if cfg.App.ScanIntervalSeconds < 0 {
		cfg.App.ScanIntervalSeconds = 0
	}

	if cfg.Process.IntervalSeconds <= 0 {
		cfg.Process.IntervalSeconds = 2
	}

	if len(cfg.Process.WebParents) == 0 {
		cfg.Process.WebParents = []string{
			"php-fpm", "php", "nginx", "apache2", "httpd",
			"node", "uvicorn", "gunicorn", "python3",
		}
	}

	if len(cfg.Process.ShellNames) == 0 {
		cfg.Process.ShellNames = []string{
			"sh", "bash", "dash", "zsh", "nc", "ncat", "socat",
			"python", "python3", "perl", "curl", "wget",
		}
	}
}

func (c *Config) ProcessEnabled() bool {
	return c.Process.Enabled != nil && *c.Process.Enabled
}

func (c *Config) ProcessDryRun() bool {
	return c.Process.DryRun == nil || *c.Process.DryRun
}

func (c *Config) ProcessKillOnlyCritical() bool {
	return c.Process.KillOnlyCritical == nil || *c.Process.KillOnlyCritical
}
