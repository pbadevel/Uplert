package watcher

import (
	"context"

	"github.com/pbadevel/Uplert/internal/model"
)

type Watcher interface {
	Run(ctx context.Context, events chan<- model.FileEvent) error
}
