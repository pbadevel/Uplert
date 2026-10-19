package rules

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/pbadevel/Uplert/internal/model"
)

type MagicMismatch struct {
	ImageExts map[string]bool
}

func (MagicMismatch) ID() string {
	return "magic_mismatch"
}

func (r MagicMismatch) Evaluate(ev model.FileEvent) []model.Finding {
	if ev.Op != model.OpCreate &&
		ev.Op != model.OpWrite &&
		ev.Op != model.OpRename {
		return nil
	}

	ext := strings.ToLower(filepath.Ext(ev.Path))

	if !r.ImageExts[ext] {
		return nil
	}

	f, err := os.Open(ev.Path)
	if err != nil {
		return nil
	}
	defer f.Close()

	buf := make([]byte, 12)
	n, err := f.Read(buf)
	if err != nil && n == 0 {
		return nil
	}

	var mismatch bool

	switch ext {
	case ".jpg", ".jpeg":
		if n < 3 || buf[0] != 0xFF || buf[1] != 0xD8 || buf[2] != 0xFF {
			mismatch = true
		}

	case ".png":
		pngSig := []byte{0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A}
		if n < 8 || !bytes.Equal(buf[:8], pngSig) {
			mismatch = true
		}

	case ".gif":
		if n < 4 || string(buf[:4]) != "GIF8" {
			mismatch = true
		}

	case ".webp":
		if n < 12 || string(buf[:4]) != "RIFF" || string(buf[8:12]) != "WEBP" {
			mismatch = true
		}
	}

	if mismatch {
		return []model.Finding{
			{
				RuleID:  MagicMismatch{}.ID(),
				Level:   model.LevelMedium,
				Message: "file extension does not match magic bytes",
				Path:    ev.Path,
				Time:    ev.Time,
			},
		}
	}

	return nil
}