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
	// Action is a machine-readable identifier (run|scan|test|edit|...).
	Action string
	// Input makes Enter open an inline value prompt (raw mode stays
	// active, so no typed bytes are lost to tcsetattr flush).
	Input bool
	// Hint is a short explanation shown when editing the item.
	Hint string
}

// pendingStash carries unread key bytes across raw-mode sessions:
// every Menu call restores the terminal (tcsetattr flushes the input
// queue), so leftovers from the previous session must survive.
var pendingStash []byte

// Menu shows an interactive selection on a TTY. Arrow keys (or j/k)
// navigate, Enter confirms. For Input items a value is collected
// in-place with a tiny line editor. Esc/Ctrl+C/q exit; the last
// return flag reports a confirmed selection.
func Menu(members []MenuItem) (MenuItem, string, bool) {
	if len(members) == 0 || !IsTerminal(os.Stdout) || !term.IsTerminal(os.Stdin.Fd()) {
		return MenuItem{}, "", false
	}

	old, rawErr := term.MakeRaw(os.Stdin.Fd())
	if rawErr != nil {
		return MenuItem{}, "", false
	}
	defer func() {
		_ = term.Restore(os.Stdin.Fd(), old)
	}()

	fmt.Print("\x1b[?25l") // hide cursor
	defer fmt.Print("\x1b[?25h")

	selected := 0

	// In raw mode ONLCR is off: plain "\n" moves down without
	// carriage return, so every printed line must use CRLF.
	crlf := func(s string) {
		fmt.Print(strings.ReplaceAll(s, "\n", "\r\n"))
	}

	paintFrame := func() {
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

		crlf(b.String())
	}

	redraw := func() {
		fmt.Printf("\r\x1b[%dA\x1b[J", len(members)+1) // clear previous frame
		paintFrame()
	}

	// Full repaint: the hint line shifts the layout on cancel.
	repaintAll := func() {
		fmt.Print("\x1b[2J\x1b[H")
		crlf(Banner(Version))
		paintFrame()
	}

	fmt.Print("\x1b[2J\x1b[H") // clear screen, cursor home
	crlf(Banner(Version))
	paintFrame()

	buf := make([]byte, 64)
	pending := append([]byte(nil), pendingStash...)
	pendingStash = nil

	for {
		if len(pending) == 0 {
			n, readErr := os.Stdin.Read(buf)
			if readErr != nil {
				return MenuItem{}, "", false
			}

			pending = append(pending, buf[:n]...)

			// A bare ESC byte alone: treat as quit (not a sequence).
			if n == 1 && pending[0] == 0x1b {
				pendingStash = pendingStash[:0]
				fmt.Print("\x1b[2J\x1b[H")
				return MenuItem{}, "", false
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
					fmt.Print("\x1b[2J\x1b[H")
					return MenuItem{}, "", false
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
				item := members[selected]
				rest := append([]byte(nil), pending[1:]...)
				pending = nil

				if item.Input {
					value, cleared, ok2, leftover := inputValue(item.Label, item.Hint, rest)
					pendingStash = leftover

					if !ok2 {
						// Cancelled: stay in the menu.
						repaintAll()

						break
					}

					if cleared {
						value = ""
					}

					fmt.Print("\x1b[2J\x1b[H")

					return item, value, true
				}

				pendingStash = rest
				fmt.Print("\x1b[2J\x1b[H")

				return item, "", true

			case b == 'q' || b == 'Q' || b == 0x03:
				pendingStash = pendingStash[:0]
				fmt.Print("\x1b[2J\x1b[H")
				return MenuItem{}, "", false

			default:
				pending = pending[1:]
			}
		}
	}
}

// inputValue runs a minimal line editor while the terminal is raw:
// printable chars echo, Backspace erases, Enter confirms, Esc cancels.
// Enter on an empty line — or 'e' while empty — means "clear the
// value" (ok=true with cleared=true). Esc reports ok=false.
func inputValue(prompt, hint string, pre []byte) (value string, cleared bool, ok bool, leftover []byte) {
	label := strings.TrimSpace(prompt)

	if hint != "" {
		fmt.Printf("\r\r\x1b[2m%s\x1b[0m\r\n", hint)
	}

	fmt.Printf("\x1b[2m%s\x1b[0m \x1b[36m>\x1b[0m ", label)

	var line []byte

	buf := make([]byte, 64)
	pending := append([]byte(nil), pre...)

	for {
		if len(pending) == 0 {
			n, err := os.Stdin.Read(buf)
			if err != nil {
				return "", false, false, nil
			}

			pending = append(pending, buf[:n]...)
		}

		consumed := 0

		for _, b := range pending {
			consumed++

			switch {
			case b == '\r' || b == '\n':
				fmt.Printf("\r")

				if len(line) == 0 {
					return "", true, true, pending[consumed:]
				}

				return string(line), false, true, pending[consumed:]

			case b == 0x1b: // Esc cancels
				fmt.Printf("\r\x1b[2J\x1b[H")

				return "", false, false, pending[consumed:]

			case b == 0x7f || b == 0x08: // Backspace
				if len(line) > 0 {
					line = line[:len(line)-1]
					fmt.Print("\b \b")
				}

			case b == 'e' || b == 'E':
				if len(line) == 0 || hasSpacesOnly(line) {
					// Fast-clear: 'e' on an (all-spaces) line.
					fmt.Printf("\r")

					return "", true, true, pending[consumed:]
				}

				line = append(line, b)
				fmt.Print(string(rune(b)))

			case b >= 0x20:
				line = append(line, b)
				fmt.Print(string(rune(b)))
			}
		}

		pending = pending[consumed:]
	}
}

// hasSpacesOnly reports whether the typed line consists of spaces
// only ('e' should still fast-clear).
func hasSpacesOnly(line []byte) bool {
	for _, b := range line {
		if b != ' ' {
			return false
		}
	}

	return true
}
