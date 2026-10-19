# Uplert

Uplert is a lightweight Go agent for Linux servers that monitors watched directories and detects suspicious file activity commonly associated with webshell uploads and RCE aftermath.

It is not a full EDR or antivirus. It focuses on practical detection around file uploads, dangerous scripts, executable files, suspicious media content, and common post-exploitation artifacts.

## Features

- [x] Recursive directory watching
- [x] Path ignore list
- [x] Dangerous file extension detection
- [x] Double extension detection
- [x] Executable file detection in watched directories
- [x] PHP-like code detection inside image files
- [x] Script-like content detection in SVG/HTML files
- [x] Suspicious web configuration detection
  - [x] `.htaccess`
  - [x] `.user.ini`
  - [x] `web.config`
- [x] Magic byte mismatch detection
- [x] Human-readable colored logs
- [x] Log levels:
  - [x] `debug`
  - [x] `info`
  - [x] `error`
- [x] Built-in test agent for local verification
- [x] Simple YAML configuration
- [x] Single static binary build support

## Requirements

- Go `1.23+`
- Linux or macOS for development
- `inotify` limits may need adjustment on large directory trees

## Quick Start

Install dependencies:

```bash
go mod tidy
```

Run in normal mode:

```bash
make run
```

Run in debug mode:

```bash
make run-debug
```

Build binary:

```bash
make build
```

The binary will be available at:

```bash
bin/uplert
```

## Configuration

Default config file:

```bash
configs/config.yaml
```

Example:

```yaml
log_level: info

watch:
  dirs:
    - ./test_uploads
    - /app/uploads
    - /var/www/uploads
  ignore:
    - ./test_uploads/cache

alerts:
  stdout: true
  webhook: ""
```

### Log Levels

Available levels:

```yaml
log_level: debug
log_level: info
log_level: error
```

Override log level using environment variable:

```bash
UPLERT_LOG_LEVEL=debug go run ./cmd/uplert --config configs/config.yaml
```

Or with Make:

```bash
make run-debug
```

## Testing

Run one test scenario:

```bash
make test-agent
```

Run continuous test loop:

```bash
make test-agent-loop
```

The test agent creates files inside:

```bash
./test_uploads
```

It generates safe test markers such as:

```text
shell.php
run.sh
photo.jpg.php
image.php.jpg
payload.png
not_image.jpg
avatar.svg
.htaccess
.user.ini
avatars/nested_shell.php
```

These files are not real malware. They contain harmless markers used to verify detection rules.

## Example Output

```text
00:12:01 INFO starting uplert watch_dirs=[./test_uploads] log_level=debug
00:12:05 DEBU file event op=create path=test_uploads/shell_1.php is_dir=false
00:12:05 WARN security finding rule=dangerous_extension path=test_uploads/shell_1.php message="dangerous file extension detected"
00:12:06 WARN security finding rule=executable_in_uploads path=test_uploads/shell_1.php message="executable file detected in watched directory"
00:12:08 WARN security finding rule=php_in_media path=test_uploads/payload_1.png message="PHP-like code found inside media file"
```

## Project Structure

```text
cmd/
  uplert/       # main agent
  testagent/    # test file generator

internal/
  alert/        # alert sinks
  app/          # orchestration
  config/       # configuration loading
  model/        # domain types
  rules/        # detection rules
  watcher/      # filesystem watcher
```

## Adding a New Rule

Create a file inside:

```text
internal/rules/
```

Implement the `Rule` interface:

```go
package rules

import "github.com/pbadevel/Uplert/internal/model"

type MyRule struct{}

func (MyRule) ID() string {
	return "my_rule"
}

func (MyRule) Evaluate(ev model.FileEvent) []model.Finding {
	// detection logic here
	return nil
}
```

Register it in:

```text
cmd/uplert/main.go
```

Example:

```go
registry := rules.NewRegistry(
	rules.MyRule{},
)
```

## Adding a New Alerter

Create a file inside:

```text
internal/alert/
```

Implement the `Alerter` interface:

```go
package alert

import (
	"context"

	"github.com/pbadevel/Uplert/internal/model"
)

type Alerter interface {
	Alert(ctx context.Context, f model.Finding) error
}
```

Possible future alerters:

- Webhook
- Telegram
- Slack
- Discord
- Syslog
- Prometheus metrics
- Loki logs

## Systemd Service

Build the binary:

```bash
make build
```

Install:

```bash
sudo cp bin/uplert /usr/local/bin/uplert
sudo mkdir -p /etc/uplert
sudo cp configs/config.yaml /etc/uplert/config.yaml
```

Create service file:

```bash
sudo nano /etc/systemd/system/uplert.service
```

Example:

```ini
[Unit]
Description=Uplert file integrity and RCE aftermath detector
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/uplert --config /etc/uplert/config.yaml
Restart=on-failure
RestartSec=5
Environment=UPLERT_LOG_LEVEL=info

[Install]
WantedBy=multi-user.target
```

Enable and start:

```bash
sudo systemctl daemon-reload
sudo systemctl enable uplert
sudo systemctl start uplert
```

View logs:

```bash
journalctl -u uplert -f
```

## Known Limitations

- Uplert does not prevent RCE.
- It detects suspicious file activity and possible post-exploitation artifacts.
- Static file scanning can produce duplicate events without debouncing.
- Large directory trees may require higher `inotify` limits.
- Process and network behavior monitoring are not implemented yet.

### Inotify Limits

Check current limit:

```bash
cat /proc/sys/fs/inotify/max_user_watches
```

Increase temporarily:

```bash
sudo sysctl fs.inotify.max_user_watches=524288
```

Increase permanently:

```bash
echo "fs.inotify.max_user_watches=524288" | sudo tee -a /etc/sysctl.d/99-inotify.conf
sudo sysctl --system
```

## Roadmap

### Stability

- [ ] Add event debouncing
- [ ] Deduplicate repeated alerts
- [ ] Reduce false positives
- [ ] Add rule cooldowns
- [ ] Add structured JSON log output option
- [ ] Add unit tests
- [ ] Add integration tests

### Detection

- [ ] Add risk scoring
- [ ] Add allowlists for known frameworks
- [ ] Add denylists for dangerous paths
- [ ] Detect ELF binaries in upload directories
- [ ] Detect `.so` libraries in upload directories
- [ ] Detect PHAR archives
- [ ] Detect obfuscated PHP patterns
- [ ] Detect high-entropy suspicious files
- [ ] Detect symlinks pointing outside watched directories
- [ ] Detect hidden files with dangerous extensions
- [ ] Detect suspicious cron entries
- [ ] Detect suspicious systemd units
- [ ] Detect modified `.env` files
- [ ] Detect modified SSH authorized keys
- [ ] Detect modified web server configs

### Alerting

- [ ] Add webhook alerter
- [ ] Add Telegram alerter
- [ ] Add Slack alerter
- [ ] Add Discord alerter
- [ ] Add syslog alerter
- [ ] Add Prometheus metrics exporter
- [ ] Add Loki-compatible log output
- [ ] Add alert batching
- [ ] Add alert severity filtering

### Runtime Security

- [ ] Add process execution monitoring
- [ ] Detect files executed from watched directories
- [ ] Detect web processes spawning shells
- [ ] Detect `curl`, `wget`, `nc`, `bash`, `sh`, `python`, `perl` child processes
- [ ] Add network connection monitoring
- [ ] Detect cloud metadata access
- [ ] Detect reverse shell patterns
- [ ] Detect secret file reads
- [ ] Add auditd integration
- [ ] Add eBPF-based runtime monitoring
- [ ] Add container-aware process tracking

### Operations

- [ ] Add config hot reload
- [ ] Add rule hot reload
- [ ] Add periodic full scan mode
- [ ] Add one-shot scan CLI mode
- [ ] Add report generation
- [ ] Add Docker image
- [ ] Add Kubernetes DaemonSet support
- [ ] Add package builds for Debian/Ubuntu
- [ ] Add Arch Linux package
- [ ] Add OpenRC init script
- [ ] Add FreeBSD support
- [ ] Add Windows support

### UX

- [ ] Add clearer startup banner
- [ ] Add `--version` flag
- [ ] Add `--help` examples
- [ ] Add sample production config
- [ ] Add documentation for each rule
- [ ] Add troubleshooting guide
- [ ] Add security policy document