package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func main() {
	dir := flag.String("dir", "./test_uploads", "directory for generated test files")
	interval := flag.Duration("interval", 3*time.Second, "pause between rounds")
	stepDelay := flag.Duration("step-delay", 200*time.Millisecond, "pause between file actions")
	once := flag.Bool("once", false, "run one scenario and exit")
	clean := flag.Bool("clean", false, "remove test dir before start")
	flag.Parse()

	if *clean {
		_ = os.RemoveAll(*dir)
	}

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}

	nestedDir := filepath.Join(*dir, "avatars")
	if err := os.MkdirAll(nestedDir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir nested:", err)
		os.Exit(1)
	}

	writeFile := func(path string, content string, perm os.FileMode) {
		if err := os.WriteFile(path, []byte(content), perm); err != nil {
			fmt.Fprintln(os.Stderr, "write:", path, err)
			return
		}
		fmt.Printf("[+] write %s\n", path)
		time.Sleep(*stepDelay)
	}

	round := 1

	runRound := func() {
		fmt.Printf("\n=== round %d ===\n", round)

		safe := filepath.Join(*dir, fmt.Sprintf("safe_%d.jpg", round))
		writeFile(
			safe,
			"\xff\xd8\xff\xe0\x00\x10JFIF\x00uplert-safe-test\n",
			0o644,
		)

		php := filepath.Join(*dir, fmt.Sprintf("shell_%d.php", round))
		writeFile(
			php,
			"<?php /* uplert-test-dangerous-extension */ ?>\n",
			0o644,
		)

		sh := filepath.Join(*dir, fmt.Sprintf("run_%d.sh", round))
		writeFile(
			sh,
			"#!/bin/sh\necho uplert-test\n",
			0o644,
		)

		double1 := filepath.Join(*dir, fmt.Sprintf("photo_%d.jpg.php", round))
		writeFile(
			double1,
			"uplert-test-double-extension\n",
			0o644,
		)

		double2 := filepath.Join(*dir, fmt.Sprintf("image_%d.php.jpg", round))
		writeFile(
			double2,
			"uplert-test-reverse-double-extension\n",
			0o644,
		)

		phtml := filepath.Join(*dir, fmt.Sprintf("template_%d.phtml", round))
		writeFile(
			phtml,
			"<?php /* uplert-test-phtml */ ?>\n",
			0o644,
		)

		phpInPng := filepath.Join(*dir, fmt.Sprintf("payload_%d.png", round))
		writeFile(
			phpInPng,
			"\x89PNG\r\n\x1a\n<?php /* uplert-test-php-in-png */ ?>\n",
			0o644,
		)

		evalInGif := filepath.Join(*dir, fmt.Sprintf("eval_%d.gif", round))
		writeFile(
			evalInGif,
			"GIF89a<?php eval(/* uplert-test */); ?>\n",
			0o644,
		)

		notImage := filepath.Join(*dir, fmt.Sprintf("not_image_%d.jpg", round))
		writeFile(
			notImage,
			"<?php /* uplert-test-magic-mismatch */ ?>\n",
			0o644,
		)

		svg := filepath.Join(*dir, fmt.Sprintf("avatar_%d.svg", round))
		writeFile(
			svg,
			`<svg xmlns="http://www.w3.org/2000/svg"><script>/* uplert-test-svg-script */</script></svg>`+"\n",
			0o644,
		)

		htaccess := filepath.Join(*dir, fmt.Sprintf(".htaccess_%d", round))
		writeFile(
			htaccess,
			"php_value auto_prepend_file uplert-test.conf\n",
			0o644,
		)

		userIni := filepath.Join(*dir, fmt.Sprintf(".user.ini_%d", round))
		writeFile(
			userIni,
			"auto_prepend_file = uplert-test.php\n",
			0o644,
		)

		hiddenPhp := filepath.Join(*dir, fmt.Sprintf(".hidden_%d.php", round))
		writeFile(
			hiddenPhp,
			"<?php /* uplert-test-hidden-php */ ?>\n",
			0o644,
		)

		nestedPhp := filepath.Join(nestedDir, fmt.Sprintf("nested_shell_%d.php", round))
		writeFile(
			nestedPhp,
			"<?php /* uplert-test-nested-php */ ?>\n",
			0o644,
		)

		if err := os.Chmod(php, 0o755); err == nil {
			fmt.Printf("[+] chmod +x %s\n", php)
			time.Sleep(*stepDelay)
		}

		if err := os.Chmod(sh, 0o755); err == nil {
			fmt.Printf("[+] chmod +x %s\n", sh)
			time.Sleep(*stepDelay)
		}

		if err := os.Chmod(nestedPhp, 0o755); err == nil {
			fmt.Printf("[+] chmod +x %s\n", nestedPhp)
			time.Sleep(*stepDelay)
		}

		renamed := filepath.Join(*dir, fmt.Sprintf("renamed_%d.jpg", round))
		if err := os.Rename(safe, renamed); err == nil {
			fmt.Printf("[+] rename %s -> %s\n", safe, renamed)
			time.Sleep(*stepDelay)
		}

		if err := os.Remove(renamed); err == nil {
			fmt.Printf("[+] remove %s\n", renamed)
			time.Sleep(*stepDelay)
		}

		round++
	}

	if *once {
		runRound()
		return
	}

	for {
		runRound()
		time.Sleep(*interval)
	}
}