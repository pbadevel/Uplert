package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type LogLevel string

const (
	LogLevelDebug LogLevel = "debug"
	LogLevelInfo  LogLevel = "info"
	LogLevelError LogLevel = "error"
)

type Config struct {
	LogLevel LogLevel `yaml:"log_level"`
	Watch    Watch    `yaml:"watch"`
	Alerts   Alerts   `yaml:"alerts"`
}

type Watch struct {
	Dirs   []string `yaml:"dirs"`
	Ignore []string `yaml:"ignore"`
}

type Alerts struct {
	Stdout  bool   `yaml:"stdout"`
	Webhook string `yaml:"webhook"`
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

	if cfg.LogLevel == "" {
		cfg.LogLevel = LogLevelInfo
	}

	return &cfg, nil
}
