package watcher

import (
	"context"

	"github.com/pbadevel/Uplert/internal/model"
)

type Noop struct{}

func NewNoop() *Noop {
	return &Noop{}
}

func (Noop) Run(ctx context.Context, _ chan<- model.FileEvent) error {
	<-ctx.Done()
	return ctx.Err()
}
