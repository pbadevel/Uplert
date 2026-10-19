package rules

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/pbadevel/Uplert/internal/model"
)

const maxScanSize = 1024 * 1024

type PHPInImage struct{}

func (PHPInImage) ID() string {
	return "php_in_image"
}

func (PHPInImage) Evaluate(ev model.FileEvent) []model.Finding {
	if ev.Op != model.OpWrite && ev.Op != model.OpRename {
		return nil
	}

	ext := strings.ToLower(filepath.Ext(ev.Path))

	imageExts := map[string]bool{
		".jpg":  true,
		".jpeg": true,
		".png":  true,
		".gif":  true,
		".webp": true,
	}

	if !imageExts[ext] {
		return nil
	}

	info, err := os.Stat(ev.Path)
	if err != nil {
		return nil
	}

	if info.IsDir() {
		return nil
	}

	if info.Size() > maxScanSize {
		return nil
	}

	data, err := os.ReadFile(ev.Path)
	if err != nil {
		return nil
	}

	suspicious := [][]byte{
		[]byte("<?php"),
		[]byte("eval("),
		[]byte("system("),
		[]byte("shell_exec("),
		[]byte("base64_decode("),
		[]byte("passthru("),
		[]byte("proc_open("),
	}

	for _, s := range suspicious {
		if bytes.Contains(data, s) {
			return []model.Finding{
				{
					RuleID:  PHPInImage{}.ID(),
					Level:   model.LevelCritical,
					Message: "PHP-like code found inside image file",
					Path:    ev.Path,
					Time:    ev.Time,
				},
			}
		}
	}

	return nil
}
