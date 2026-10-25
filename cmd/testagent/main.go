package main

import (
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/pbadevel/Uplert/internal/testgen"
)

func testgenRound(dir string) (int, error) {
	return testgen.Round(dir)
}

func main() {
	dir := flag.String("dir", "./test_uploads", "directory for generated marker files")
	interval := flag.Duration("interval", 3*time.Second, "pause between rounds")
	once := flag.Bool("once", false, "run one round and exit")
	spawn := flag.Bool("spawn", false, "also start the live actor process")
	clean := flag.Bool("clean", false, "remove test dir before start")
	flag.Parse()

	if *clean {
		_ = os.RemoveAll(*dir)
	}

	if err := os.MkdirAll(*dir, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "mkdir:", err)
		os.Exit(1)
	}

	if *once {
		if _, err := testgenRound(*dir); err != nil {
			fmt.Fprintln(os.Stderr, "round:", err)
			os.Exit(1)
		}

		if *spawn {
			_, _ = testgen.Spawn(*dir)
		}

		return
	}

	for {
		if _, err := testgenRound(*dir); err != nil {
			fmt.Fprintln(os.Stderr, "round:", err)
		}

		time.Sleep(*interval)
	}
}
