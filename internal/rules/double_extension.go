package rules

import (
	"path/filepath"
	"strings"

	"github.com/pbadevel/Uplert/internal/model"
)

type DoubleExtension struct {
	ScriptExts map[string]bool
}

func (DoubleExtension) ID() string {
	return "double_extension"
}

func (r DoubleExtension) Evaluate(ev model.FileEvent) []model.Finding {
	if ev.Op != model.OpCreate && ev.Op != model.OpRename {
		return nil
	}

	base := filepath.Base(ev.Path)
	parts := strings.Split(base, ".")

	if len(parts) < 3 {
		return nil
	}

	for i := 0; i < len(parts)-1; i++ {
		ext := "." + strings.ToLower(parts[i])

		if r.ScriptExts[ext] {
			return []model.Finding{
				{
					RuleID:  DoubleExtension{}.ID(),
					Level:   model.LevelHigh,
					Message: "possible double extension detected",
					Path:    ev.Path,
					Time:    ev.Time,
				},
			}
		}
	}

	return nil
}
