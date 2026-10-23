package rules

import (
	"bytes"
	"io"
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
	// MaxSize is the full-file scan limit. Files larger than this are
	// either skipped (TailBytes == 0) or scanned head+tail (see TailBytes).
	MaxSize int64
	// TailBytes enables tail scanning for files larger than MaxSize:
	// the first MaxSize bytes and the last TailBytes bytes are checked.
	// This catches payloads appended to large media files.
	TailBytes int64
}

func (r ContentRule) ID() string {
	return r.RuleID
}

func (r ContentRule) Evaluate(ev model.FileEvent) []model.Finding {
	allowed := map[model.Op]bool{
		model.OpCreate: true,
		model.OpWrite:  true,
		model.OpRename: true,
		model.OpScan:   true,
	}

	if !allowed[ev.Op] {
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

	if matchesPattern(readHeadTail(ev.Path, info, r.MaxSize, r.TailBytes), r.Patterns) {
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

	return nil
}

// readHeadTail returns the bytes that should be scanned:
// the whole file if it fits into limit, otherwise head+tail windows.
func readHeadTail(path string, info os.FileInfo, limit, tail int64) []byte {
	size := info.Size()

	if limit <= 0 || size <= limit {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		return data
	}

	head, err := readWindow(path, 0, limit)
	if err != nil {
		return nil
	}

	if tail <= 0 {
		return head
	}

	tailData, err := readWindow(path, size-tail, tail)
	if err != nil {
		return head
	}

	return append(head, tailData...)
}

func readWindow(path string, offset, length int64) ([]byte, error) {
	if offset < 0 {
		offset = 0
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	buf := make([]byte, length)
	n, err := io.ReadFull(io.NewSectionReader(f, offset, length), buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return buf[:n], err
	}

	return buf[:n], nil
}

func matchesPattern(data []byte, patterns [][]byte) bool {
	if data == nil {
		return false
	}

	lower := bytes.ToLower(data)

	for _, pattern := range patterns {
		if bytes.Contains(lower, bytes.ToLower(pattern)) {
			return true
		}
	}

	return false
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
