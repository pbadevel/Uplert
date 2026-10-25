// Package testgen creates harmless marker files that exercise every
// detection rule. It is shipped inside the uplert binary (uplert test)
// and also powers cmd/testagent for scripted rounds.
package testgen

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

// Files are safe markers, never real malware.
func writeMarker(dir, name, content string, perm os.FileMode) error {
	path := filepath.Join(dir, name)

	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		return fmt.Errorf("write %s: %w", name, err)
	}

	fmt.Printf("[uplert-test] %s\n", path)

	return nil
}

// Round writes one full scenario into dir and returns the number of
// created files. Subdirectories are created as needed.
func Round(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}

	created := 0

	step := func(err error) {
		if err == nil {
			created++
		} else {
			fmt.Fprintln(os.Stderr, err)
		}
	}

	step(writeMarker(dir, "uplert_safe.jpg", "\xff\xd8\xff\xe0 uplert-safe", 0o644))
	step(writeMarker(dir, "uplert_shell.php", "<?php /* marker */ ?>", 0o644))
	step(writeMarker(dir, "uplert_run.sh", "#!/bin/sh\necho marker\n", 0o644))
	step(writeMarker(dir, "uplert_photo.jpg.php", "marker", 0o644))
	step(writeMarker(dir, "uplert_image.php.jpg", "marker", 0o644))
	step(writeMarker(dir, "uplert_payload.png", "\x89PNG\r\n\x1a\n<?php /* marker */ ?>\n", 0o644))
	step(writeMarker(dir, "uplert_eval.gif", "GIF89a<?php eval(/* marker */); ?>\n", 0o644))
	step(writeMarker(dir, "uplert_not_image.jpg", "<?php /* marker */ ?>\n", 0o644))
	step(writeMarker(dir, "uplert_avatar.svg", `<svg><script>/* marker */</script></svg>`+"\n", 0o644))
	step(writeMarker(dir, ".uplert_hidden.php", "<?php /* marker */ ?>\n", 0o644))

	nested := filepath.Join(dir, "nested")

	step(func() error { return os.MkdirAll(nested, 0o755) }())
	step(writeMarker(nested, "uplert_nested.php", "<?php /* marker */ ?>\n", 0o644))

	conf := filepath.Join(dir, "conf")

	step(func() error { return os.MkdirAll(conf, 0o755) }())
	step(writeMarker(conf, ".htaccess", "php_value auto_prepend_file marker.txt\n", 0o644))
	step(writeMarker(conf, ".user.ini", "auto_prepend_file = marker.php\n", 0o644))

	if err := os.Chmod(filepath.Join(dir, "uplert_shell.php"), 0o755); err == nil {
		fmt.Printf("[uplert-test] +x %s\n", filepath.Join(dir, "uplert_shell.php"))
	}

	if err := os.Chmod(filepath.Join(dir, "uplert_run.sh"), 0o755); err == nil {
		fmt.Printf("[uplert-test] +x %s\n", filepath.Join(dir, "uplert_run.sh"))
	}

	return created, nil
}

// Spawn starts a live actor process inside dir: a shell script that
// keeps writing marker files. With the process detector enabled and
// dry_run=false, uplert will detect and kill it — this demonstrates
// the response pipeline end-to-end. The script removes itself on
// start of each run is not needed: it is tiny and killed quickly.
func Spawn(dir string) (int, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, err
	}

	script := filepath.Join(dir, "uplert_actor.sh")

	body := "#!/bin/sh\n" +
		"while true; do\n" +
		"\techo '<?php /* actor marker */ ?>' > \"$0.d/$$.php\" 2>/dev/null || echo marker > \"$0.out\"\n" +
		"\tsleep 1\n" +
		"done\n"

	if err := os.WriteFile(script, []byte(body), 0o755); err != nil {
		return 0, fmt.Errorf("write actor: %w", err)
	}

	cmd := exec.Command("/bin/sh", script)
	cmd.Dir = dir

	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("start actor: %w", err)
	}

	done := make(chan error, 1)

	go func() { done <- cmd.Wait() }()

	// Do not zombie the child: forget it in the background.
	go func() { _ = <-done }()

	fmt.Printf("[uplert-test] actor pid=%d script=%s (agent with --process --kill will stop it)\n", cmd.Process.Pid, script)

	return cmd.Process.Pid, nil
}
