package rules

import (
	"path/filepath"
	"strings"

	"github.com/pbadevel/Uplert/internal/model"
)

type DangerousExtension struct {
	Exts map[string]bool
}

func (r DangerousExtension) ID() string {
	return "dangerous_extension"
}

func (r DangerousExtension) Evaluate(ev model.FileEvent) []model.Finding {
	if ev.Op != model.OpCreate &&
		ev.Op != model.OpRename &&
		ev.Op != model.OpScan {
		return nil
	}

	ext := strings.ToLower(filepath.Ext(ev.Path))

	if !r.Exts[ext] {
		return nil
	}

	return []model.Finding{
		{
			RuleID:  r.ID(),
			Level:   model.LevelHigh,
			Message: "dangerous file extension detected",
			Path:    ev.Path,
			Time:    ev.Time,
		},
	}
}
