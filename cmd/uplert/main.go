package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/charmbracelet/log"
	"github.com/pbadevel/Uplert/internal/alert"
	"github.com/pbadevel/Uplert/internal/app"
	"github.com/pbadevel/Uplert/internal/config"
	"github.com/pbadevel/Uplert/internal/model"
	"github.com/pbadevel/Uplert/internal/rules"
	"github.com/pbadevel/Uplert/internal/watcher"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatal("load config", "error", err)
	}
	if lvl := os.Getenv("UPLERT_LOG_LEVEL"); lvl != "" {
		cfg.LogLevel = config.LogLevel(strings.ToLower(lvl))
	}

	var logLevel slog.Level
	switch cfg.LogLevel {
	case config.LogLevelDebug:
		logLevel = slog.LevelDebug
	case config.LogLevelInfo:
		logLevel = slog.LevelInfo
	case config.LogLevelError:
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	// Создаём логгер с цветами
	logger := log.NewWithOptions(os.Stdout, log.Options{
		Level:           log.Level(logLevel),
		ReportTimestamp: true,
		TimeFormat:      "15:04:05",
	})

	// Оборачиваем в slog.Logger для совместимости
	slogLogger := slog.New(logger)

	slogLogger.Info("starting uplert",
		"watch_dirs", cfg.Watch.Dirs,
		"log_level", cfg.LogLevel,
	)

	dangerousExts := map[string]bool{
		".php":   true,
		".phtml": true,
		".php5":  true,
		".phar":  true,
		".sh":    true,
		".bash":  true,
		".cgi":   true,
		".pl":    true,
		".py":    true,
		".jsp":   true,
		".jspx":  true,
		".asp":   true,
		".aspx":  true,
	}

	mediaExts := []string{
		".jpg",
		".jpeg",
		".png",
		".gif",
		".webp",
	}

	phpPatterns := [][]byte{
		[]byte("<?php"),
		[]byte("<?= "),
		[]byte("eval("),
		[]byte("assert("),
		[]byte("base64_decode("),
		[]byte("gzinflate("),
		[]byte("gzuncompress("),
		[]byte("str_rot13("),
		[]byte("shell_exec("),
		[]byte("system("),
		[]byte("passthru("),
		[]byte("proc_open("),
		[]byte("popen("),
		[]byte("pcntl_exec("),
		[]byte("$_get"),
		[]byte("$_post"),
		[]byte("$_request"),
		[]byte("$_cookie"),
	}

	scriptPatterns := [][]byte{
		[]byte("<script"),
		[]byte("onload="),
		[]byte("javascript:"),
		[]byte("data:text/html;base64"),
	}

	webConfigPatterns := [][]byte{
		[]byte("auto_prepend_file"),
		[]byte("auto_append_file"),
		[]byte("php_value"),
		[]byte("php_flag"),
		[]byte("sethandler"),
		[]byte("addtype"),
		[]byte("application/x-httpd-php"),
	}

	registry := rules.NewRegistry(
		rules.DangerousExtension{
			Exts: dangerousExts,
		},

		rules.DoubleExtension{
			ScriptExts: dangerousExts,
		},

		rules.ExecutableInUploads{},

		rules.MagicMismatch{
			ImageExts: map[string]bool{
				".jpg":  true,
				".jpeg": true,
				".png":  true,
				".gif":  true,
				".webp": true,
			},
		},

		rules.ContentRule{
			RuleID:     "php_in_media",
			Level:      model.LevelCritical,
			Message:    "PHP-like code found inside media file",
			Extensions: mediaExts,
			Patterns:   phpPatterns,
			MaxSize:    2 * 1024 * 1024,
		},

		rules.ContentRule{
			RuleID:     "script_in_html_or_svg",
			Level:      model.LevelHigh,
			Message:    "script-like content found in HTML/SVG file",
			Extensions: []string{".svg", ".html", ".htm", ".xhtml"},
			Patterns:   scriptPatterns,
			MaxSize:    2 * 1024 * 1024,
		},

		rules.ContentRule{
			RuleID:    "suspicious_web_config",
			Level:     model.LevelCritical,
			Message:   "suspicious web server/php configuration file detected",
			Basenames: []string{".htaccess", ".user.ini", "web.config"},
			Patterns:  webConfigPatterns,
			MaxSize:   512 * 1024,
		},

		rules.ContentRule{
			RuleID:  "shebang_in_watched_dir",
			Level:   model.LevelMedium,
			Message: "script shebang detected in watched directory",
			Patterns: [][]byte{
				[]byte("#!"),
			},
			MaxSize: 64 * 1024,
		},
	)

	var alerters []alert.Alerter
	if cfg.Alerts.Stdout {
		alerters = append(alerters, alert.NewLog(slogLogger))
	}
	if len(alerters) == 0 {
		alerters = append(alerters, alert.NewLog(slogLogger))
	}

	application := app.New(
		slogLogger,
		watcher.NewFSNotify(cfg.Watch.Dirs, cfg.Watch.Ignore),
		registry,
		alerters...,
	)

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	if err := application.Run(ctx); err != nil {
		slogLogger.Error("app failed", "error", err)
		os.Exit(1)
	}
}
