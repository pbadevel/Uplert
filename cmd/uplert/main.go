package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/pbadevel/Uplert/internal/alert"
	"github.com/pbadevel/Uplert/internal/app"
	"github.com/pbadevel/Uplert/internal/config"
	"github.com/pbadevel/Uplert/internal/rules"
	"github.com/pbadevel/Uplert/internal/watcher"
)

func main() {
	configPath := flag.String("config", "configs/config.yaml", "path to config file")
	flag.Parse()

	cfg, err := config.Load(*configPath)
	if err != nil {
		slog.Error("load config", "error", err)
		os.Exit(1)
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

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))

	logger.Info("starting uplert",
		"watch_dirs", cfg.Watch.Dirs,
		"log_level", cfg.LogLevel,
	)

	registry := rules.NewRegistry(
		rules.DangerousExtension{
			Exts: map[string]bool{
				".php":   true,
				".phtml": true,
				".php5":  true,
				".phar":  true,
				".sh":    true,
			},
		},
	)

	var alerters []alert.Alerter
	if cfg.Alerts.Stdout {
		alerters = append(alerters, alert.NewLog(logger))
	}
	if len(alerters) == 0 {
		alerters = append(alerters, alert.NewLog(logger))
	}

	application := app.New(
		logger,
		watcher.NewNoop(),
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
		logger.Error("app failed", "error", err)
		os.Exit(1)
	}
}
