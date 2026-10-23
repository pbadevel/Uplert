package rules

import (
	"os"

	"github.com/pbadevel/Uplert/internal/model"
)

type ExecutableInUploads struct{}

func (ExecutableInUploads) ID() string {
	return "executable_in_uploads"
}

func (ExecutableInUploads) Evaluate(ev model.FileEvent) []model.Finding {
	if ev.Op != model.OpCreate &&
		ev.Op != model.OpChmod &&
		ev.Op != model.OpRename &&
		ev.Op != model.OpScan {
		return nil
	}

	info, err := os.Stat(ev.Path)
	if err != nil {
		return nil
	}

	if info.IsDir() {
		return nil
	}

	if info.Mode()&0o111 != 0 {
		return []model.Finding{
			{
				RuleID:  ExecutableInUploads{}.ID(),
				Level:   model.LevelHigh,
				Message: "executable file detected in watched directory",
				Path:    ev.Path,
				Time:    ev.Time,
			},
		}
	}

	return nil
}
