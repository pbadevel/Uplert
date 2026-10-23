package ui

import (
	"fmt"
	"os"
	"strings"
)

// ANSI escape helpers, zero dependencies.
const (
	ansiReset   = "\x1b[0m"
	ansiBold    = "\x1b[1m"
	ansiDim     = "\x1b[2m"
	ansiCyan    = "\x1b[36m"
	ansiGreen   = "\x1b[32m"
	ansiYellow  = "\x1b[33m"
	ansiMagenta = "\x1b[35m"
	ansiWhite   = "\x1b[37m"
)

var logoLines = []string{
	` ██  ██    ██▄▄    ▄▄██ ▄▄██ ██▄▄▄ `,
	` ██  ██ ▄▄ ██ ▀▄  ██ ▀▄ ██▀  ██ ▀▀ `,
	` ██  ██  ▄▄██ ▄▄▄ ██ ▄▄ ▀██▄ ██ ▄▄ `,
	`  █████       █▀▀    █▀▀ ▄██  █▀▀▀ `,
}

var logoColors = []string{
	ansiCyan,
	fmt.Sprintf("%s\x1b[96m", ansiBold),
	fmt.Sprintf("%s\x1b[96m", ansiBold),
	ansiCyan,
}

// Version is set by the app (build info or ldflags).
var Version = "dev"

// Banner returns the colored startup banner.
func Banner(version string) string {
	var b strings.Builder

	b.WriteString("\n")

	for i, line := range logoLines {
		b.WriteString(logoColors[i])
		b.WriteString(line)
		b.WriteString(ansiReset)
		b.WriteString("\n")
	}

	b.WriteString("\n")
	b.WriteString("  " + ansiWhite + ansiBold + "uplert")
	b.WriteString(ansiReset + ansiDim)
	b.WriteString(fmt.Sprintf(" v%s", version))
	b.WriteString(ansiReset)
	b.WriteString("\n")

	b.WriteString("  " + ansiDim + "lightweight webshell & RCE aftermath detector" + ansiReset)
	b.WriteString("\n")

	b.WriteString("  " + ansiGreen + "made by " + ansiBold + "pbadev" + ansiReset)
	b.WriteString("  " + ansiDim + "https://github.com/pbadev" + ansiReset)
	b.WriteString("\n\n")

	return b.String()
}

// IsTerminal reports whether fd refers to a terminal.
func IsTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}

	return info.Mode()&os.ModeCharDevice != 0
}

// PrintError prints a red-styled error line.
func PrintError(msg string) {
	fmt.Fprintln(os.Stderr, ansiBold+"\x1b[31m✘"+" "+msg+ansiReset)
}

// PrintSuccess prints a green-styled check line.
func PrintSuccess(msg string) {
	fmt.Println(ansiGreen + "✔" + ansiReset + " " + msg)
}
