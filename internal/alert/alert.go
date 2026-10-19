package alert

import (
	"context"

	"github.com/pbadevel/Uplert/internal/model"
)

type Alerter interface {
	Alert(ctx context.Context, f model.Finding) error
}
