package watcher

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/pbadevel/Uplert/internal/model"
)

type FSNotify struct {
	dirs   []string
	ignore []string

	mu      sync.Mutex
	watched map[string]struct{}
}

func NewFSNotify(dirs []string, ignore []string) *FSNotify {
	return &FSNotify{
		dirs:    dirs,
		ignore:  ignore,
		watched: make(map[string]struct{}),
	}
}

func (w *FSNotify) Run(ctx context.Context, events chan<- model.FileEvent) error {
	fw, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create fsnotify watcher: %w", err)
	}
	defer fw.Close()

	for _, dir := range w.dirs {
		dir = filepath.Clean(dir)

		if err := w.addRecursive(fw, dir); err != nil {
			return fmt.Errorf("watch dir %s: %w", dir, err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return nil

		case event, ok := <-fw.Events:
			if !ok {
				return nil
			}

			path := filepath.Clean(event.Name)

			if w.isIgnored(path) {
				continue
			}

			op, ok := convertOp(event.Op)
			if !ok {
				continue
			}

			isDir := false

			if op == model.OpCreate ||
				op == model.OpWrite ||
				op == model.OpChmod {
				info, err := os.Stat(path)
				if err == nil {
					isDir = info.IsDir()
				}
			}

			if op == model.OpCreate && isDir {
				if err := w.addRecursive(fw, path); err != nil {
					return fmt.Errorf("add recursive watch for %s: %w", path, err)
				}
			}

			if isDir && (op == model.OpWrite || op == model.OpChmod) {
				continue
			}

			if op == model.OpRemove || op == model.OpRename {
				w.forget(path)
			}

			fileEvent := model.FileEvent{
				Op:    op,
				Path:  path,
				IsDir: isDir,
				Time:  time.Now(),
			}

			if err := w.send(ctx, events, fileEvent); err != nil {
				return err
			}

		case err, ok := <-fw.Errors:
			if !ok {
				return nil
			}

			return fmt.Errorf("fsnotify error: %w", err)
		}
	}
}

func (w *FSNotify) addRecursive(fw *fsnotify.Watcher, root string) error {
	root = filepath.Clean(root)

	info, err := os.Stat(root)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", root)
	}

	return filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if !d.IsDir() {
			return nil
		}

		path = filepath.Clean(path)

		if w.isIgnored(path) {
			return filepath.SkipDir
		}

		w.mu.Lock()
		defer w.mu.Unlock()

		if _, ok := w.watched[path]; ok {
			return nil
		}

		if err := fw.Add(path); err != nil {
			return fmt.Errorf("add watch %s: %w", path, err)
		}

		w.watched[path] = struct{}{}

		return nil
	})
}

func (w *FSNotify) isIgnored(path string) bool {
	path = filepath.Clean(path)

	for _, ignore := range w.ignore {
		ignore = filepath.Clean(ignore)

		if path == ignore {
			return true
		}

		if strings.HasPrefix(path, ignore+string(os.PathSeparator)) {
			return true
		}
	}

	return false
}

func (w *FSNotify) forget(path string) {
	path = filepath.Clean(path)

	w.mu.Lock()
	defer w.mu.Unlock()

	if _, ok := w.watched[path]; !ok {
		return
	}

	delete(w.watched, path)

	prefix := path + string(os.PathSeparator)

	for watchedPath := range w.watched {
		if strings.HasPrefix(watchedPath, prefix) {
			delete(w.watched, watchedPath)
		}
	}
}

func (w *FSNotify) send(
	ctx context.Context,
	events chan<- model.FileEvent,
	event model.FileEvent,
) error {
	select {
	case events <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func convertOp(op fsnotify.Op) (model.Op, bool) {
	switch {
	case op&fsnotify.Create != 0:
		return model.OpCreate, true

	case op&fsnotify.Write != 0:
		return model.OpWrite, true

	case op&fsnotify.Remove != 0:
		return model.OpRemove, true

	case op&fsnotify.Rename != 0:
		return model.OpRename, true

	case op&fsnotify.Chmod != 0:
		return model.OpChmod, true

	default:
		return "", false
	}
}