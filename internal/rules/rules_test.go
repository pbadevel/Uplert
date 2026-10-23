package rules

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pbadevel/Uplert/internal/model"
)

var testTime = time.Now()

const phpPayload = "<?php eval(base64_decode($_POST['x'])); ?>"

func newRegistry(t *testing.T) *Registry {
	t.Helper()

	return NewRegistry(
		DangerousExtension{Exts: map[string]bool{".php": true}},
		DoubleExtension{ScriptExts: map[string]bool{".php": true}},
		ExecutableInUploads{},
		MagicMismatch{ImageExts: map[string]bool{".png": true, ".jpg": true}},
		ContentRule{
			RuleID:     "php_in_media",
			Level:      model.LevelCritical,
			Message:    "PHP-like code found inside media file",
			Extensions: []string{".png", ".jpg"},
			Patterns:   [][]byte{[]byte("<?php"), []byte("eval(")},
			MaxSize:    1024,
			TailBytes:  64,
		},
		ContentRule{
			RuleID:    "suspicious_web_config",
			Level:     model.LevelCritical,
			Message:   "suspicious web server/php configuration file detected",
			Basenames: []string{".htaccess", ".user.ini"},
			Patterns:  [][]byte{[]byte("php_value"), []byte("auto_prepend_file")},
			MaxSize:   512,
		},
	)
}

func write(t *testing.T, dir, name, content string, perm os.FileMode) string {
	t.Helper()

	path := filepath.Join(dir, name)

	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatal(err)
	}

	return path
}

func evalAll(t *testing.T, dir string) map[string]bool {
	t.Helper()

	got := map[string]bool{}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	rules := newRegistry(t)

	for _, e := range entries {
		for _, op := range []model.Op{model.OpCreate, model.OpWrite, model.OpChmod, model.OpScan} {
			for _, f := range rules.Evaluate(model.FileEvent{
				Op:   op,
				Path: filepath.Join(dir, e.Name()),
				Time: testTime,
			}) {
				got[f.RuleID+"|"+filepath.Base(f.Path)] = true
			}
		}
	}

	return got
}

func wantOne(t *testing.T, got map[string]bool, key string, want bool) {
	t.Helper()

	if got[key] != want {
		t.Fatalf("%q: got=%v want=%v", key, got[key], want)
	}
}

func TestDangerousExtension(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "shell.php", phpPayload, 0o644)

	got := evalAll(t, dir)

	wantOne(t, got, "dangerous_extension|shell.php", true)
}

func TestDoubleExtension(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "image.php.jpg", "hello", 0o644)

	got := evalAll(t, dir)

	wantOne(t, got, "double_extension|image.php.jpg", true)
}

func TestExecutableInUploads(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "run.sh", "#!/bin/sh\n", 0o755)
	write(t, dir, "quiet.sh", "#!/bin/sh\n", 0o644)

	got := evalAll(t, dir)

	wantOne(t, got, "executable_in_uploads|run.sh", true)
	wantOne(t, got, "executable_in_uploads|quiet.sh", false)
}

func TestMagicMismatch(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "fake.jpg", "plain text not jpeg", 0o644)
	write(t, dir, "ok.jpg", "\xff\xd8\xff\xe0 jfif", 0o644)

	got := evalAll(t, dir)

	wantOne(t, got, "magic_mismatch|fake.jpg", true)
	wantOne(t, got, "magic_mismatch|ok.jpg", false)
}

func TestPHPInMedia(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "shell.png", "\x89PNG\r\n\x1a\n"+phpPayload, 0o644)
	write(t, dir, "clean.png", "\x89PNG\r\n\x1a\nsafe image", 0o644)

	got := evalAll(t, dir)

	wantOne(t, got, "php_in_media|shell.png", true)
	wantOne(t, got, "php_in_media|clean.png", false)
}

func TestPHPInMediaTailOfLargeFile(t *testing.T) {
	dir := t.TempDir()

	// > MaxSize (1024): head is clean, the payload is in the tail
	// (last 64 bytes) — must still be detected.
	head := "\x89PNG\r\n\x1a\n"

	long := make([]byte, 2048)
	for i := range long {
		long[i] = '.'
	}

	write(t, dir, "big.png", head+string(long)+phpPayload, 0o644)

	got := evalAll(t, dir)

	wantOne(t, got, "php_in_media|big.png", true)
}

func TestSuspiciousWebConfig(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, ".htaccess", "php_value auto_prepend_file evil.php\n", 0o644)
	write(t, dir, "backup.htaccess.bak", "php_value auto_prepend_file evil.php\n", 0o644)

	got := evalAll(t, dir)

	wantOne(t, got, "suspicious_web_config|.htaccess", true)
	wantOne(t, got, "suspicious_web_config|backup.htaccess.bak", false)
}

func TestMatchName(t *testing.T) {
	cases := []struct {
		actual, configured string
		want               bool
	}{
		{"php-fpm", "php-fpm", true},
		{"php-fpm8.2", "php-fpm", true},
		{"node", "node", true},
		{"nodejs", "node", false},
		{"bash", "bash", true},
		{"bash-exe", "bash", true}, // non-letter boundary is accepted
		{"sh", "dash", false},
	}

	for _, c := range cases {
		if got := matchName(c.actual, c.configured); got != c.want {
			t.Errorf("matchName(%q, %q) = %v, want %v",
				c.actual, c.configured, got, c.want)
		}
	}
}
