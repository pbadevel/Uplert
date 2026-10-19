package rules

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/pbadevel/Uplert/internal/model"
)

type ContentRule struct {
	RuleID     string
	Level      model.Level
	Message    string
	Extensions []string
	Basenames  []string
	Patterns   [][]byte
	MaxSize    int64
}

func (r ContentRule) ID() string {
	return r.RuleID
}

func (r ContentRule) Evaluate(ev model.FileEvent) []model.Finding {
	if ev.Op != model.OpCreate &&
		ev.Op != model.OpWrite &&
		ev.Op != model.OpRename {
		return nil
	}

	if !r.matchesPath(ev.Path) {
		return nil
	}

	info, err := os.Stat(ev.Path)
	if err != nil {
		return nil
	}

	if info.IsDir() {
		return nil
	}

	if r.MaxSize > 0 && info.Size() > r.MaxSize {
		return nil
	}

	data, err := os.ReadFile(ev.Path)
	if err != nil {
		return nil
	}

	lower := bytes.ToLower(data)

	for _, pattern := range r.Patterns {
		lowerPattern := bytes.ToLower(pattern)

		if bytes.Contains(lower, lowerPattern) {
			return []model.Finding{
				{
					RuleID:  r.ID(),
					Level:   r.Level,
					Message: r.Message,
					Path:    ev.Path,
					Time:    ev.Time,
				},
			}
		}
	}

	return nil
}

func (r ContentRule) matchesPath(path string) bool {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))

	extOK := len(r.Extensions) == 0
	for _, e := range r.Extensions {
		if strings.ToLower(e) == ext {
			extOK = true
			break
		}
	}

	baseOK := len(r.Basenames) == 0
	for _, b := range r.Basenames {
		if strings.ToLower(b) == base {
			baseOK = true
			break
		}
	}

	return extOK && baseOK
}