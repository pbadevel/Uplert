package watcher

import (
	"context"

	"github.com/pbadevel/Uplert/internal/model"
)

// Noop is a fake watcher used by one-shot scan mode.
type Noop struct{}

func (Noop) Run(ctx context.Context, _ chan<- model.FileEvent) error {
	<-ctx.Done()
	return ctx.Err()
}
