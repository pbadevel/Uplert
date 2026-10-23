package ui

import (
	"fmt"
	"os"
	"strings"

	"github.com/charmbracelet/x/term"
)

// MenuItem is one entry of the interactive menu.
type MenuItem struct {
	Label string
	// Action is a machine-readable identifier (run|scan|test|...).
	Action string
}

// Menu shows an interactive selection on a TTY, navigated with
// arrow keys (or j/k), confirmed with Enter. Esc/Ctrl+C/q exit.
func Menu(members []MenuItem) (MenuItem, bool) {
	if len(members) == 0 || !IsTerminal(os.Stdout) || !term.IsTerminal(os.Stdin.Fd()) {
		return MenuItem{}, false
	}

	old, err := term.MakeRaw(os.Stdin.Fd())
	if err != nil {
		return MenuItem{}, false
	}
	defer func() {
		_ = term.Restore(os.Stdin.Fd(), old)
	}()

	fmt.Print("\x1b[?25l") // hide cursor
	defer fmt.Print("\x1b[?25h")

	selected := 0

	redraw := func() {
		fmt.Printf("\x1b[%dA\x1b[J", len(members)+1) // clear previous frame
		drawFrame(members, selected)
	}

	fmt.Print("\x1b[2J\x1b[H") // clear screen, cursor home
	fmt.Print(Banner(Version))
	drawFrame(members, selected)

	buf := make([]byte, 64)
	var pending []byte

	for {
		if len(pending) == 0 {
			n, readErr := os.Stdin.Read(buf)
			if readErr != nil {
				return MenuItem{}, false
			}

			pending = append(pending, buf[:n]...)

			// A bare ESC byte alone: treat as quit (no sequence start).
			if n == 1 && pending[0] == 0x1b {
				fmt.Print("\x1b[2J\x1b[H")
				return MenuItem{}, false
			}
		}

		for len(pending) > 0 {
			b := pending[0]

			switch {
			case b == 0x1b && len(pending) == 1:
				pending = nil // wait for the rest of the sequence

			case b == 0x1b && len(pending) >= 3:
				if pending[1] == '[' && pending[2] == 'A' {
					selected = (selected - 1 + len(members)) % len(members)
					redraw()
				} else if pending[1] == '[' && pending[2] == 'B' {
					selected = (selected + 1) % len(members)
					redraw()
				} else {
					// some partially delivered sequence: consume
					sel := members[selected]
					fmt.Print("\x1b[2J\x1b[H")

					return sel, false
				}

				pending = pending[3:]

			case b == 'j' || b == 'J':
				selected = (selected + 1) % len(members)
				redraw()
				pending = pending[1:]

			case b == 'k' || b == 'K':
				selected = (selected - 1 + len(members)) % len(members)
				redraw()
				pending = pending[1:]

			case b == '\r' || b == '\n':
				fmt.Print("\x1b[2J\x1b[H")

				return members[selected], true

			case b == 'q' || b == 'Q' || b == 0x03:
				fmt.Print("\x1b[2J\x1b[H")

				return MenuItem{}, false

			default:
				pending = pending[1:]
			}
		}
	}
}

func drawFrame(members []MenuItem, selected int) {
	var b strings.Builder

	b.WriteString("\x1b[1m  выберите действие\x1b[0m  ")
	b.WriteString("\x1b[2m(↑/↓, j/k, Enter, q — выход)\x1b[0m\n")

	for i, item := range members {
		cursor, style := "  ", ""

		if i == selected {
			cursor, style = "▸ ", "\x1b[36m\x1b[1m"
		}

		b.WriteString(cursor + style + item.Label + "\x1b[0m\n")
	}

	fmt.Print(b.String())
}
