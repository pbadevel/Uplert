package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	charmlog "github.com/charmbracelet/log"

	"github.com/pbadevel/Uplert/internal/alert"
	"github.com/pbadevel/Uplert/internal/app"
	"github.com/pbadevel/Uplert/internal/config"
	"github.com/pbadevel/Uplert/internal/model"
	"github.com/pbadevel/Uplert/internal/process"
	"github.com/pbadevel/Uplert/internal/rules"
	"github.com/pbadevel/Uplert/internal/testgen"
	"github.com/pbadevel/Uplert/internal/ui"
	"github.com/pbadevel/Uplert/internal/watcher"
)

var (
	configPath = flag.String("config", "configs/config.yaml", "path to config file (shorthand -c)")
	showVer    = flag.Bool("version", false, "print version and exit")

	// Runtime overrides for the YAML config.
	flagWorkers      = flag.Int("workers", 0, "override app.workers (shorthand -w)")
	flagBuffer       = flag.Int("buffer", 0, "override app.events_buffer")
	flagDebounce     = flag.Int("debounce", 0, "override app.debounce_ms, ms")
	flagScanInterval = flag.Int("scan-interval", 0, "override app.scan_interval_seconds, sec")
	flagScanOnStart  = flag.Bool("scan-on-start", false, "override app.scan_on_start")
	flagLogLevel     = flag.String("log-level", "", "override log_level (debug|info|error, -l)")
	flagLogFormat    = flag.String("log-format", "", "override log_format (text|json)")
	flagWatch        = flag.String("watch", "", "override watch.dirs, comma-separated (shorthand -W)")
	flagIgnore       = flag.String("ignore", "", "override watch.ignore, comma-separated (shorthand -I)")
	flagWebhook      = flag.String("webhook", "", "override alerts.webhook")
	flagTgToken      = flag.String("tg-token", "", "override alerts.telegram_bot_token")
	flagTgChat       = flag.String("tg-chat", "", "override alerts.telegram_chat_id")
	flagProcess      = flag.Bool("process", false, "enable process detector (override process.enabled)")
	flagKill         = flag.Bool("kill", false, "actually kill instead of dry-run (override process.dry_run)")

	workerAlias = flag.Int("w", 0, "shorthand of --workers")
	bufferAlias = flag.Int("b", 0, "shorthand of --buffer")
	debounceAl  = flag.Int("d", 0, "shorthand of --debounce")
	intervalAl  = flag.Int("i", 0, "shorthand of --scan-interval")
	levelAlias  = flag.String("l", "", "shorthand of --log-level")
	watchAlias  = flag.String("W", "", "shorthand of --watch")
	ignoreAlias = flag.String("I", "", "shorthand of --ignore")
	configAlias = flag.String("c", "", "shorthand of --config")
	testSpawn   = flag.Bool("spawn", false, "uplert test: also start a live actor process (kill demo)")
)

// versionOverride is injected at build time:
//
//	go build -ldflags "-X main.versionOverride=v1.2.3"
var versionOverride string

func main() {
	version := resolveVersion()
	ui.Version = version

	flag.CommandLine.Usage = usage

	// Subcommands: uplert run|scan --config ...
	args := os.Args[1:]

	sub := ""

	known := map[string]bool{"run": true, "scan": true, "test": true}
	if len(args) > 0 && known[args[0]] {
		sub = args[0]
		args = args[1:]
	}

	_ = flag.CommandLine.Parse(args)

	if *configAlias != "" {
		*configPath = *configAlias
	}

	if *showVer {
		fmt.Printf("uplert %s\n", version)
		return
	}

	switch sub {
	case "run":
		headless(loadConfig(*configPath), version, true)
		return
	case "scan":
		runScan(loadConfig(*configPath), version)
		return
	case "test":
		runTestGen(loadConfig(*configPath), *testSpawn)
		return
	}

	// Interactive mode.
	if ui.IsTerminal(os.Stdout) {
		showMenu(loadConfig(*configPath), *configPath, version)
		return
	}

	headless(loadConfig(*configPath), version, true)
}

// applyOverrides patches the loaded config with explicitly provided
// CLI flags. Only flags the user actually passed are consulted.
func applyOverrides(cfg *config.Config) {
	set := map[string]bool{}

	flag.CommandLine.Visit(func(f *flag.Flag) {
		set[f.Name] = true
	})

	if set["workers"] || set["w"] {
		if v := pickInt(set, "workers", *flagWorkers, "w", *workerAlias); v > 0 {
			cfg.App.Workers = v
		}
	}

	if set["buffer"] || set["b"] {
		if v := pickInt(set, "buffer", *flagBuffer, "b", *bufferAlias); v > 0 {
			cfg.App.EventsBuffer = v
		}
	}

	if set["debounce"] || set["d"] {
		if v := pickInt(set, "debounce", *flagDebounce, "d", *debounceAl); v > 0 {
			cfg.App.DebounceMS = v
		}
	}

	if set["scan-interval"] || set["i"] {
		if v := pickInt(set, "scan-interval", *flagScanInterval, "i", *intervalAl); v >= 0 {
			cfg.App.ScanIntervalSeconds = v
		}
	}

	if set["scan-on-start"] {
		cfg.App.ScanOnStart = *flagScanOnStart
	}

	if set["log-level"] {
		cfg.LogLevel = config.LogLevel(strings.ToLower(*flagLogLevel))
	} else if set["l"] {
		cfg.LogLevel = config.LogLevel(strings.ToLower(*levelAlias))
	}

	if set["log-format"] {
		cfg.LogFormat = config.LogFormat(strings.ToLower(*flagLogFormat))
	}

	if set["watch"] || set["W"] {
		if set["watch"] {
			cfg.Watch.Dirs = splitList(*flagWatch)
		} else {
			cfg.Watch.Dirs = splitList(*watchAlias)
		}
	}

	if set["ignore"] || set["I"] {
		if set["ignore"] {
			cfg.Watch.Ignore = splitList(*flagIgnore)
		} else {
			cfg.Watch.Ignore = splitList(*ignoreAlias)
		}
	}

	if set["webhook"] {
		cfg.Alerts.Webhook = *flagWebhook
	}

	if set["tg-token"] {
		cfg.Alerts.Telegram = *flagTgToken
	}

	if set["tg-chat"] {
		cfg.Alerts.TelegramCID = *flagTgChat
	}

	if set["process"] {
		yes := *flagProcess
		cfg.Process.Enabled = &yes
	}

	if set["kill"] {
		dry := !*flagKill
		cfg.Process.DryRun = &dry
	}
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}

	var out []string

	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)

		if part != "" {
			out = append(out, part)
		}
	}

	return out
}

func pickInt(set map[string]bool, long string, longVal int, short string, shortVal int) int {
	if set[long] {
		return longVal
	}

	return shortVal
}

func usage() {
	fmt.Print(ui.Banner(ui.Version))
	fmt.Println(`  usage: uplert [command] [flags]

  commands:
    (none)      interactive menu (default in a TTY)
    run         run the agent headless (use this for systemd)
    scan        one-shot scan and exit

  config flags (override the YAML file):
    -c, --config <file>       path to config (default configs/config.yaml)
    -w, --workers <n>         app.workers
        --buffer <n>          app.events_buffer
    -d, --debounce <ms>       app.debounce_ms
    -i, --scan-interval <s>   app.scan_interval_seconds
        --scan-on-start       app.scan_on_start (bool flag)
    -l, --log-level <lvl>     debug | info | error
        --log-format <fmt>    text | json
    -W, --watch <dir,dir>     replace watch.dirs
    -I, --ignore <p,p>        replace watch.ignore
        --webhook <url>       alerts.webhook
        --tg-token <tok>      alerts.telegram_bot_token (with --tg-chat)
        --tg-chat <id>        alerts.telegram_chat_id
        --process             enable the process detector
        --kill                actually kill (from dry-run)
    --version                 print version and exit

  examples:
    uplert run --config /etc/uplert/config.yaml
    uplert run -W /var/www/app/uploads -w 4
    uplert run -l debug --process
    uplert scan --webhook https://hooks.example.com/uplert -W /srv/uploads`)
}

func showMenu(cfg *config.Config, cfgPath, version string) {
	for {
		choice, value, ok := ui.Menu([]ui.MenuItem{
			{Label: "▶  Run agent (watch & alert)", Action: "run"},
			{Label: "🔎 One-shot scan", Action: "scan"},
			{Label: "🧪 Run test agent", Action: "test"},
			{Label: "⚙  Config: edit settings", Action: "edit"},
			{Label: "📄 Show config file", Action: "config"},
			{Label: "⭘ Exit", Action: "exit"},
		})
		if !ok {
			return
		}

		_ = value

		switch choice.Action {
		case "run":
			ui.PrintSuccess("starting agent (Ctrl+C to stop)")
			headless(cfg, version, false)
			return

		case "scan":
			printFindings(collectFindings(cfg), cfg)
			ui.PrintSuccess("scan complete")
			return

		case "test":
			runTestGen(cfg, false)
			ui.PrintSuccess("test files created — try 🔎 One-shot scan now")
			return

		case "edit":
			showSettingsEditor(cfg, cfgPath)

		case "config":
			showConfigFile(cfgPath)
			waitKey()

		case "exit":
			return
		}
	}
}

func showConfigFile(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		ui.PrintError(fmt.Sprintf("cannot read %s: %v", path, err))
		return
	}

	fmt.Printf("\r\n\x1b[2m──── %s ────\x1b[0m\r\n", path)
	fmt.Print(strings.ReplaceAll(string(data), "\n", "\r\n"))
}

// showSettingsEditor is a small form-based editor: pick a setting,
// a value is typed right inside the menu, then everything is saved
// back to the YAML file (or opened in $EDITOR).
func showSettingsEditor(cfg *config.Config, cfgPath string) {
	for {
		choice, value, ok := ui.Menu([]ui.MenuItem{
			{Label: fmt.Sprintf("  workers          %d", cfg.App.Workers),
				Action: "workers", Input: true,
				Hint: "Worker goroutines that evaluate rules in parallel. 2–4 is fine for small upload dirs."},
			{Label: fmt.Sprintf("  events_buffer    %d", cfg.App.EventsBuffer),
				Action: "buffer", Input: true,
				Hint: "Channel buffer for file events. Increase if dirs change heavily (bursts of uploads)."},
			{Label: fmt.Sprintf("  debounce_ms      %d", cfg.App.DebounceMS),
				Action: "debounce", Input: true,
				Hint: "Coalesces repeated events for the same path (create+write+chmod → one evaluation)."},
			{Label: fmt.Sprintf("  scan_interval_s  %d", cfg.App.ScanIntervalSeconds),
				Action: "interval", Input: true,
				Hint: "Fallback full-scan interval in seconds; 0 (or 'e' on empty) disables. Esc cancels."},
			{Label: boolItem("  scan_on_start   ", cfg.App.ScanOnStart),
				Action: "scan-on-start",
				Hint:   "Scan existing files once at startup. Enter toggles."},
			{Label: fmt.Sprintf("  log_level        %s", cfg.LogLevel),
				Action: "log-level", Input: true,
				Hint: "debug | info | error. Use debug for troubleshooting, info for daily use."},
			{Label: fmt.Sprintf("  log_format       %s", cfg.LogFormat),
				Action: "log-format", Input: true,
				Hint: "text (color logs) or json (SIEM/journalctl-friendly)."},
			{Label: fmt.Sprintf("  watch.dirs       %s", joinList(cfg.Watch.Dirs)),
				Action: "dirs", Input: true,
				Hint: "Comma-separated upload dirs, e.g. /var/www/app/uploads. Replaces the whole list."},
			{Label: fmt.Sprintf("  watch.ignore     %s", joinList(cfg.Watch.Ignore)),
				Action: "ignore", Input: true,
				Hint: "Comma-separated paths to skip (cache, .git, node_modules). Replaces the list."},
			{Label: strItem("  webhook         ", cfg.Alerts.Webhook),
				Action: "webhook", Input: true,
				Hint: "URL that receives a JSON POST per finding. Enter/'e' on empty clears (disables); Esc cancels."},
			{Label: strItem("  telegram        ", maskedTelegram(cfg)),
				Action: "telegram", Input: true,
				Hint: "Bot token (from @BotFather); chat id is asked next. Enter/'e' on empty clears; Esc cancels.",
			},
			{Label: boolItem("  process.enabled ", cfg.ProcessEnabled()),
				Action: "process",
				Hint:   "Watch processes spawned by web servers / run from watch dirs. Enter toggles."},
			{Label: boolItem("  dry_run         ", cfg.ProcessDryRun()),
				Action: "dry-run",
				Hint:   "true = log kills without acting. Switch false only after studying dry-run logs."},
			{Label: "\x1b[33m  ♻  Reset to defaults\x1b[0m", Action: "reset",
				Hint: "Factory defaults for engine/logger/process; watch.dirs, ignores and alerts are kept."},
			{Label: "  📝 Open in $EDITOR", Action: "editor",
				Hint: "Edit the raw YAML with your $EDITOR (nano, vim...)."},
			{Label: "\x1b[32m  💾 Save\x1b[0m", Action: "save",
				Hint: "Write settings back to the YAML file (validated before writing). Esc keeps, 'e' clears a value where allowed."},
			{Label: "  ↩  Back", Action: "back",
				Hint: "Return to the main menu."},
		})
		if !ok {
			return
		}

		// For Input items value=="" means "cleared explicitly" (Enter on
		// an empty line or the 'e' shortcut), Esc never reaches here.

		switch choice.Action {
		case "reset":
			fresh := config.Default()
			// Preserve what is specific to this server.
			fresh.Watch = cfg.Watch
			fresh.Alerts.Webhook = cfg.Alerts.Webhook
			fresh.Alerts.Telegram = cfg.Alerts.Telegram
			fresh.Alerts.TelegramCID = cfg.Alerts.TelegramCID
			*cfg = fresh
			ui.PrintSuccess("reset to defaults (watch dirs, ignores and alerts kept)")
		case "back":
			return

		case "save":
			if err := saveConfig(cfg, cfgPath); err != nil {
				ui.PrintError(err.Error())
			} else {
				ui.PrintSuccess("saved to " + cfgPath)
			}

		case "editor":
			if err := openEditor(cfg, cfgPath); err != nil {
				ui.PrintError(err.Error())
				waitKey()
			}

		case "workers":
			if v, err := parseNonNeg(value); err == nil {
				cfg.App.Workers = v
			}

		case "buffer":
			if v, err := parseNonNeg(value); err == nil {
				cfg.App.EventsBuffer = v
			}

		case "debounce":
			if v, err := parseNonNeg(value); err == nil {
				cfg.App.DebounceMS = v
			}

		case "interval":
			if v, err := parseNonNeg(value); err == nil {
				cfg.App.ScanIntervalSeconds = v // 0 disables the fallback scan
			}

		case "scan-on-start":
			cfg.App.ScanOnStart = !cfg.App.ScanOnStart

		case "process":
			yes := !cfg.ProcessEnabled()
			cfg.Process.Enabled = &yes

		case "dry-run":
			dry := !cfg.ProcessDryRun()
			cfg.Process.DryRun = &dry

		case "log-level":
			if value != "" {
				cfg.LogLevel = lvlFor("log_level", value)
			}

		case "log-format":
			if value != "" {
				cfg.LogFormat = fmtFor("log_format", value)
			}

		case "dirs":
			// An empty list would break config validation: keep old.
			if lst := splitList(value); len(lst) > 0 {
				cfg.Watch.Dirs = lst
			}

		case "ignore":
			cfg.Watch.Ignore = splitList(value)

		case "webhook":
			cfg.Alerts.Webhook = strings.TrimSpace(value)

		case "telegram":
			cfg.Alerts.Telegram = strings.TrimSpace(value)
			cfg.Alerts.TelegramCID = strings.TrimSpace(promptPlain("telegram_chat_id"))
		}
	}
}

func parseNonNeg(s string) (int, error) {
	s = strings.TrimSpace(s)

	return strconv.Atoi(s)
}

func maskedTelegram(cfg *config.Config) string {
	if cfg.Alerts.Telegram == "" {
		return "—"
	}

	return "set"
}

func joinList(items []string) string {
	if len(items) == 0 {
		return "—"
	}

	return strings.Join(items, ", ")
}

func boolItem(label string, v bool) string {
	value := "\x1b[33mfalse\x1b[0m"

	if v {
		value = "\x1b[32mtrue\x1b[0m"
	}

	return label + value
}

func strItem(label, v string) string {
	if v == "" {
		return label + "—"
	}

	return label + "set"
}

func lvlFor(_ string, s string) config.LogLevel { return config.LogLevel(s) }

func fmtFor(_ string, s string) config.LogFormat { return config.LogFormat(s) }

// promptPlain asks for a value after an inline menu input, terminal
// is already back in cooked mode (no pending bytes to flush).
func promptPlain(label string) string {
	fmt.Printf("\r\n\x1b[2m%s: \x1b[0m", label)

	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')

	return strings.TrimSpace(line)
}

func openEditor(cfg *config.Config, path string) error {
	editBin := strings.TrimSpace(os.Getenv("EDITOR"))

	if editBin == "" {
		ui.PrintError("set $EDITOR to use this (e.g. export EDITOR=nano)")
		waitKey()

		return nil
	}

	cmd := exec.Command(editBin, path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor %s: %w", editBin, err)
	}

	// Re-load whatever the user just saved.
	fresh, err := config.Load(path)
	if err != nil {
		return fmt.Errorf("re-load config: %w", err)
	}

	applyOverrides(fresh)
	*cfg = *fresh

	return nil
}

func saveConfig(cfg *config.Config, path string) error {
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	// Never write a config the program would refuse to load next time.
	var probe config.Config

	if err := yaml.Unmarshal(out, &probe); err != nil {
		return fmt.Errorf("encode config: %w", err)
	}

	if err := probe.Validate(); err != nil {
		return fmt.Errorf("invalid settings: %w", err)
	}

	if err := os.WriteFile(path, append(header, out...), 0o600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}

	return nil
}

var header = []byte("# uplert config (saved by the interactive editor)\n")

// loadConfig loads the config or exits with a message. CLI flags take
// precedence over the YAML file.
func loadConfig(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		ui.PrintError(fmt.Sprintf("failed to load config: %v", err))
		os.Exit(1)
	}

	applyOverrides(cfg)

	return cfg
}

func buildLogger(cfg *config.Config) *slog.Logger {
	var slevel slog.Level

	switch cfg.LogLevel {
	case config.LogLevelDebug:
		slevel = slog.LevelDebug
	case config.LogLevelError:
		slevel = slog.LevelError
	default:
		slevel = slog.LevelInfo
	}

	if cfg.LogFormat == config.LogFormatJSON {
		return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slevel}))
	}

	return slog.New(charmlog.NewWithOptions(os.Stdout, charmlog.Options{
		Level:           charmlog.Level(slevel),
		ReportTimestamp: true,
		TimeFormat:      "15:04:05",
	}))
}

func buildAlerters(cfg *config.Config, log *slog.Logger) []alert.Alerter {
	alerters := make([]alert.Alerter, 0, 3)

	if cfg.Alerts.ConsoleEnabled() {
		alerters = append(alerters, alert.NewLog(log))
	}

	if cfg.Alerts.Webhook != "" {
		alerters = append(alerters, alert.NewWebhook(cfg.Alerts.Webhook, 5*time.Second))
	}

	if cfg.Alerts.Telegram != "" && cfg.Alerts.TelegramCID != "" {
		alerters = append(alerters, alert.NewTelegram(cfg.Alerts.Telegram, cfg.Alerts.TelegramCID))
	}

	if len(alerters) == 0 {
		alerters = append(alerters, alert.NewLog(log))
	}

	return alerters
}

func buildRegistry() *rules.Registry {
	dangerousExts := map[string]bool{
		".php": true, ".phtml": true, ".php3": true, ".php4": true,
		".php5": true, ".php7": true, ".phps": true, ".pht": true,
		".phar": true, ".inc": true,
		".sh": true, ".bash": true, ".zsh": true, ".cgi": true,
		".pl": true, ".py": true, ".jsp": true, ".jspx": true,
		".asp": true, ".aspx": true, ".shtml": true,
	}

	phpPatterns := [][]byte{
		[]byte("<?php"),
		[]byte("<?= "),
		[]byte("<?="),
		[]byte("eval("),
		[]byte("assert("),
		[]byte("base64_decode("),
		[]byte("gzinflate("),
		[]byte("gzuncompress("),
		[]byte("str_rot13("),
		[]byte("shell_exec("),
		[]byte("system("),
		[]byte("passthru("),
		[]byte("proc_open("),
		[]byte("popen("),
		[]byte("pcntl_exec("),
		[]byte("preg_replace("),
		[]byte("$_get"),
		[]byte("$_post"),
		[]byte("$_request"),
		[]byte("$_cookie"),
		[]byte("$_server"),
	}

	scriptPatterns := [][]byte{
		[]byte("<script"),
		[]byte("onload="),
		[]byte("javascript:"),
		[]byte("data:text/html;base64"),
	}

	webConfigPatterns := [][]byte{
		[]byte("auto_prepend_file"),
		[]byte("auto_append_file"),
		[]byte("php_value"),
		[]byte("php_flag"),
		[]byte("sethandler"),
		[]byte("addtype"),
		[]byte("application/x-httpd-php"),
	}

	return rules.NewRegistry(
		rules.DangerousExtension{Exts: dangerousExts},
		rules.DoubleExtension{ScriptExts: dangerousExts},
		rules.ExecutableInUploads{},
		rules.MagicMismatch{
			ImageExts: map[string]bool{
				".jpg": true, ".jpeg": true, ".png": true,
				".gif": true, ".webp": true,
			},
		},
		rules.ContentRule{
			RuleID:     "php_in_media",
			Level:      model.LevelCritical,
			Message:    "PHP-like code found inside media file",
			Extensions: []string{".jpg", ".jpeg", ".png", ".gif", ".webp"},
			Patterns:   phpPatterns,
			MaxSize:    2 * 1024 * 1024,
			TailBytes:  128 * 1024,
		},
		rules.ContentRule{
			RuleID:     "script_in_html_or_svg",
			Level:      model.LevelHigh,
			Message:    "script-like content found in HTML/SVG file",
			Extensions: []string{".svg", ".html", ".htm", ".xhtml"},
			Patterns:   scriptPatterns,
			MaxSize:    2 * 1024 * 1024,
		},
		rules.ContentRule{
			RuleID:    "suspicious_web_config",
			Level:     model.LevelCritical,
			Message:   "suspicious web server/php configuration file detected",
			Basenames: []string{".htaccess", ".user.ini", "web.config"},
			Patterns:  webConfigPatterns,
			MaxSize:   512 * 1024,
		},
		rules.ContentRule{
			RuleID:   "shebang_in_watched_dir",
			Level:    model.LevelMedium,
			Message:  "script shebang detected in watched directory",
			Patterns: [][]byte{[]byte("#!")},
			MaxSize:  64 * 1024,
		},
	)
}

func buildProcessRules(cfg *config.Config) *rules.ProcessRegistry {
	return rules.NewProcessRegistry(
		rules.ExecFromWatchDir{Dirs: absDirs(cfg.Watch.Dirs)},
		rules.WebSpawnedShell{
			WebParents: toSet(cfg.Process.WebParents),
			ShellNames: toSet(cfg.Process.ShellNames),
		},
	)
}

func headless(cfg *config.Config, _ string, withBanner bool) {
	// Banner only for a human at a terminal; journals/Docker stay clean.
	if withBanner && ui.IsTerminal(os.Stdout) {
		fmt.Print(strings.ReplaceAll(ui.Banner(ui.Version), "\n", "\r\n"))
	}

	log := buildLogger(cfg)

	log.Info("starting uplert",
		"version", ui.Version,
		"watch_dirs", cfg.Watch.Dirs,
		"log_level", cfg.LogLevel,
	)

	runApp(cfg, log)
}

func runApp(cfg *config.Config, log *slog.Logger) {
	var detector process.ProcessDetector
	if cfg.ProcessEnabled() {
		detector = process.NewDetector(
			log, cfg.Watch.Dirs,
			cfg.Process.WebParents, cfg.Process.ShellNames,
			cfg.Process.IntervalSeconds,
		)
	}

	application := app.New(
		log,
		watcher.NewFSNotify(log, cfg.Watch.Dirs, cfg.Watch.Ignore),
		buildRegistry(),
		cfg.App,
		cfg.Watch,
		detector,
		buildProcessRules(cfg),
		&process.Policy{
			Enabled:          cfg.ProcessEnabled(),
			DryRun:           cfg.ProcessDryRun(),
			KillOnlyCritical: cfg.ProcessKillOnlyCritical(),
		},
		buildAlerters(cfg, log)...,
	)

	// Red "killed" line for humans in text-log mode.
	if cfg.LogFormat != config.LogFormatJSON {
		application.RedKills()
	}

	ctx, stop := signalCtx()
	defer stop()

	if err := application.Run(ctx); err != nil {
		log.Error("uplert fatal", "error", err)
		os.Exit(1)
	}
}

func runScan(cfg *config.Config, version string) {
	if ui.IsTerminal(os.Stdout) {
		fmt.Print(ui.Banner(version))
	}

	findings := collectFindings(cfg)

	if len(findings) == 0 {
		ui.PrintSuccess("no findings")
		return
	}

	for _, f := range findings {
		fmt.Printf("%s %s %s (%s)\n",
			"⚠", f.Level, f.Path, f.RuleID)
	}

	ui.PrintError(fmt.Sprintf("%d finding(s)", len(findings)))
	os.Exit(1)
}

func collectFindings(cfg *config.Config) []model.Finding {
	log := buildLogger(cfg)

	application := app.New(
		log,
		watcher.Noop{},
		buildRegistry(),
		cfg.App,
		cfg.Watch,
		nil, nil, nil,
	)

	return application.ScanOnce(context.Background())
}

func printFindings(findings []model.Finding, _ *config.Config) {
	for _, f := range findings {
		fmt.Printf("%s %s %s (%s)\n", "⚠", f.Level, f.Path, f.RuleID)
	}
}

// runTestGen writes the harmless marker set into the first watched
// directory (subfolder "uplert-test") so every rule can fire.
func runTestGen(cfg *config.Config, withActor bool) {
	target := "test_uploads"

	if len(cfg.Watch.Dirs) > 0 {
		target = filepath.Join(filepath.Clean(cfg.Watch.Dirs[0]), "uplert-test")
	}

	fmt.Printf("\r\ntarget: %s\r\n\r\n", target)

	n, err := testgen.Round(target)
	if err != nil {
		ui.PrintError(err.Error())
		return
	}

	ui.PrintSuccess(fmt.Sprintf("created %d marker files (safe, upstream rules will trigger)", n))

	if withActor {
		if _, err := testgen.Spawn(target); err != nil {
			ui.PrintError(err.Error())
		}
	}

	waitKey()
}

func nonEmpty(s string) string {
	if s == "" {
		return "-"
	}

	return s
}

func resolveVersion() string {
	if versionOverride != "" {
		return versionOverride
	}

	if bi, ok := debug.ReadBuildInfo(); ok {
		if bi.Main.Version != "(devel)" && bi.Main.Version != "" {
			return strings.TrimPrefix(bi.Main.Version, "v")
		}

		rev := ""
		for _, s := range bi.Settings {
			if s.Key == "vcs.revision" {
				rev = s.Value
			}
		}

		if len(rev) > 12 {
			return "dev+" + rev[:12]
		}
	}

	return "dev"
}

func absDirs(dirs []string) []string {
	out := make([]string, 0, len(dirs))

	for _, d := range dirs {
		a, err := filepath.EvalSymlinks(d)
		if err != nil {
			a, _ = filepath.Abs(d)
		}

		out = append(out, filepath.Clean(a))
	}

	return out
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, i := range items {
		m[i] = true
	}

	return m
}

func waitKey() {
	fmt.Print("\n\x1b[2m нажмите Enter, чтобы продолжить…\x1b[0m ")

	buf := make([]byte, 1)
	_, _ = os.Stdin.Read(buf)

	fmt.Println()
}

func signalCtx() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(
		context.Background(), os.Interrupt, syscall.SIGTERM)
}
