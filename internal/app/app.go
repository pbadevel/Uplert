package app

import (
	"context"
	"fmt"
	"log/slog"
	"github.com/pbadevel/Uplert/internal/alert"
	"github.com/pbadevel/Uplert/internal/model"
	"github.com/pbadevel/Uplert/internal/rules"
	"github.com/pbadevel/Uplert/internal/watcher"
)

type App struct {
	log      *slog.Logger
	watcher  *watcher.FSNotify
	rules    *rules.Registry
	alerters []alert.Alerter
}

func New(
	log *slog.Logger,
	w *watcher.FSNotify,
	registry *rules.Registry,
	alerters ...alert.Alerter,
) *App {
	return &App{
		log:      log,
		watcher:  w,
		rules:    registry,
		alerters: alerters,
	}
}

func (a *App) Run(ctx context.Context) error {
	events := make(chan model.FileEvent, 100)
	errs := make(chan error, 1)

	go func() {
		defer close(events)
		if err := a.watcher.Run(ctx, events); err != nil && ctx.Err() == nil {
			errs <- fmt.Errorf("watcher failed: %w", err)
		}
	}()

	for {
		select {
		case <-ctx.Done():
			return nil
		case err := <-errs:
			return err
		case ev, ok := <-events:
			if !ok {
				return nil
			}
			a.log.Debug("file event",
				"op", ev.Op,
				"path", ev.Path,
				"is_dir", ev.IsDir,
			)
			a.handle(ctx, ev)
		}
	}
}

func (a *App) handle(ctx context.Context, ev model.FileEvent) {
	findings := a.rules.Evaluate(ev)
	for _, finding := range findings {
		for _, alerter := range a.alerters {
			if err := alerter.Alert(ctx, finding); err != nil {
				a.log.Error("alert failed",
					"rule", finding.RuleID,
					"error", err,
				)
			}
		}
	}
}
