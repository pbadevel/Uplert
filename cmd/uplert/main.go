package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
	"time"

	charmlog "github.com/charmbracelet/log"

	"github.com/pbadevel/Uplert/internal/alert"
	"github.com/pbadevel/Uplert/internal/app"
	"github.com/pbadevel/Uplert/internal/config"
	"github.com/pbadevel/Uplert/internal/model"
	"github.com/pbadevel/Uplert/internal/process"
	"github.com/pbadevel/Uplert/internal/rules"
	"github.com/pbadevel/Uplert/internal/ui"
	"github.com/pbadevel/Uplert/internal/watcher"
)

var (
	configPath = flag.String("config", "configs/config.yaml", "path to config file")
	showVer    = flag.Bool("version", false, "print version and exit")
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

	known := map[string]bool{"run": true, "scan": true}
	if len(args) > 0 && known[args[0]] {
		sub = args[0]
		args = args[1:]
	}

	// In a non-TTY (systemd) Go flag still accepts -config.
	if sub != "" || len(args) > 0 {
		_ = flag.CommandLine.Parse(args)
	}

	if *showVer {
		fmt.Printf("uplert %s\n", version)
		return
	}

	switch sub {
	case "run":
		headless(loadConfig(*configPath), version)
		return
	case "scan":
		runScan(loadConfig(*configPath), version)
		return
	}

	// Interactive mode.
	if ui.IsTerminal(os.Stdout) {
		showMenu(loadConfig(*configPath), version)
		return
	}

	headless(loadConfig(*configPath), version)
}

func usage() {
	fmt.Print(ui.Banner(ui.Version))
	fmt.Println(`  usage: uplert [command] [flags]

  commands:
    menu           interactive menu (default in a TTY)
    run            run the agent headless (use this for systemd)
    scan           one-shot scan and exit

  flags:
    --config <file>   path to config (default configs/config.yaml)
    --version         print version and exit

  examples:
    uplert run --config /etc/uplert/config.yaml
    uplert scan --config /etc/uplert/config.yaml`)
}

func showMenu(cfg *config.Config, version string) {
	for {
		choice, ok := ui.Menu([]ui.MenuItem{
			{Label: "▶  Run agent (watch & alert)", Action: "run"},
			{Label: "🔎 One-shot scan", Action: "scan"},
			{Label: "🧪 Run test agent", Action: "test"},
			{Label: "✏  Show config", Action: "config"},
			{Label: "⭘ Exit", Action: "exit"},
		})
		if !ok {
			return
		}

		switch choice.Action {
		case "run":
			ui.PrintSuccess("starting agent (Ctrl+C to stop)")
			headless(cfg, version)
			return

		case "scan":
			printFindings(collectFindings(cfg), cfg)
			ui.PrintSuccess("scan complete")
			return

		case "test":
			runTestAgent()
			ui.PrintSuccess("test agent finished")
			return

		case "config":
			fmt.Printf("\nWatching: %s\nIgnore:   %s\nAlerts:   stdout=%v webhook=%s\n",
				cfg.Watch.Dirs, cfg.Watch.Ignore, cfg.Alerts.Stdout, nonEmpty(cfg.Alerts.Webhook))
			waitKey()

		case "exit":
			return
		}
	}
}

// loadConfig loads the config or exits with a message.
func loadConfig(path string) *config.Config {
	cfg, err := config.Load(path)
	if err != nil {
		ui.PrintError(fmt.Sprintf("failed to load config: %v", err))
		os.Exit(1)
	}

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

	if cfg.Alerts.Stdout {
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

func headless(cfg *config.Config, _ string) {
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

func runTestAgent() {
	runGoCmd("go", "run", "./cmd/testagent", "-dir", "./test_uploads", "-once", "-clean")
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

func runGoCmd(name string, args ...string) {
	if _, err := exec.LookPath(name); err != nil {
		ui.PrintError("'go' not found in PATH — cannot run test agent")
		return
	}

	if err := exec.Command(name, args...).Run(); err != nil {
		ui.PrintError(fmt.Sprintf("test agent failed: %v", err))
	}
}
