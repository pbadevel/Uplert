package alert

import (
	"context"
	"log/slog"

	"github.com/pbadevel/Uplert/internal/model"
)

type Log struct {
	log *slog.Logger
}

func NewLog(log *slog.Logger) *Log {
	return &Log{log: log}
}

func (l *Log) Alert(_ context.Context, f model.Finding) error {
	l.log.Warn("security finding",
		"rule", f.RuleID,
		"level", string(f.Level),
		"path", f.Path,
		"message", f.Message,
	)
	return nil
}
