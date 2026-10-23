# Uplert

<p align="center">
  <b>Lightweight webshell &amp; RCE aftermath detector for Linux servers.</b><br>
  One static binary. No eBPF. No SIEM. No signature databases.<br>
  <sub>made by <b>@pbadev</b></sub>
</p>

---

```text
watch upload dirs → detect malicious uploads → detect spawned shells
→ alert (stdout / webhook / Telegram / JSON) → optional kill (dry-run safe)
```

Uplert solves a narrow but very common problem: **a user uploads a file through
your web app and it lands in `uploads/`.** Uplert watches that folder in
real time with `inotify`, inspects uploads, and catches the typical aftermath:
a webshell, a PHP payload inside an image, a reverse shell spawned by php-fpm.

**Footprint:** ~8 MB static binary, ~13 MB RSS in idle. Works on any Linux from
kernel 3.x — no eBPF, no kernel modules, no rules database to download.

## Comparison with heavyweight tools

| | **uplert** | Falco | Wazuh | maldet |
|---|---|---|---|---|
| Binary size | ~8 MB | tens of MB | agent + server | Perl + ClamAV |
| Idle RAM (agent) | **~13 MB** | ~100 MB+ | ~50–150 MB | hundreds of MB |
| Kernel requirements | none | eBPF/module | systemd, auditd | none |
| Setup time | **< 2 min** | ~30 min | hours/days | ~30 min |
| Webshell semantics (PHP in image, double ext, `.htaccess`) | **yes** | no | no | signature only |
| Real-time (inotify) | **yes** | syscalls | cron-like FIM | no (cron) |
| Response (kill) | optional, dry-run safe | no | no | no |
| External infra required | **none** | sidekick | manager + ES | ClamAV |

Uplert is not an EDR and does not replace Falco/Wazuh. It is the tool you
install **now, on a cheap VPS**, while nobody signed off on a SIEM.

## Features

- ✅ **Recursive inotify watching** with debouncing and dedup
- ✅ **Dangerous extensions** (`.php`, `.phtml`, `.phar`, `.py`, `.jsp` and more)
- ✅ **Double extensions** (`image.php.jpg`)
- ✅ **PHP in images / media** — head+tail content scan of big files too
- ✅ **Script in SVG/HTML**
- ✅ **Suspicious web configs** (`.htaccess`, `.user.ini`, `web.config`)
- ✅ **Magic-byte mismatch** (`.jpg` that is not a JPEG)
- ✅ **Executable bit** in watched dirs
- ✅ **Shebang** in watched dirs
- ✅ **Process detection**: exec from watched dir, web process spawning shells
- ✅ **Response engine**: dry-run by default, explicit opt-in for real kills
- ✅ **Alerts**: colored stdout, JSON, webhook, Telegram bot
- ✅ **One-shot scan**: `uplert scan` for CI and cron jobs
- ✅ **TUI menu**: arrow keys, live dashboard (see below)
- ✅ **systemd unit, Docker image, install script**

## Quick Start

```bash
# 1. download & install
curl -fsSL https://raw.githubusercontent.com/pbadev/Uplert/main/scripts/install.sh | sh

# 2. point it at your uploads
sudo $EDITOR /etc/uplert/config.yaml

# 3. find existing evil files (exit code 1 if anything found!)
uplert scan

# 4. run in a terminal to see what it does (interactive menu on a TTY)
uplert

# 5. production
sudo systemctl enable --now uplert
```

From source:

```bash
git clone https://github.com/pbadev/Uplert
cd Uplert && make build
./bin/uplert run --config configs/config.yaml
```

## TUI menu

In a terminal `uplert` opens an interactive menu — plain ANSI, zero extra
dependencies, keyboard only:

```text
 ▸ ▶  Run agent (watch & alert)
   🔎 One-shot scan
   🧪 Run test agent
   ✏  Show config
   ⭘ Exit
```

Navigate with `↑/↓` or `j/k`, confirm with `Enter`, quit with `q`/`Esc`.
In systemd/Docker contexts (no TTY) it runs as a headless agent.

## CLI

```text
uplert run     agent loop (systemd builds on this)
uplert scan    one-shot scan, exit code 1 if findings
uplert --version
```

## Configuration

```yaml
log_level: info        # debug | info | error
# log_format: json     # emit structured JSON (journalctl/SIEM friendly)

app:
  events_buffer: 4096
  workers: 2
  debounce_ms: 300
  scan_interval_seconds: 60   # fallback sweep
  scan_on_start: true

watch:
  dirs:
    - /var/www/app/uploads
  ignore:
    - /var/www/app/uploads/cache
    - /var/www/app/.git
    - /var/www/app/node_modules

process:
  enabled: false              # enable after studying dry-run output
  dry_run: true               # true = log only, never kill
  kill_only_critical: true
  interval_seconds: 2
  web_parents: [php-fpm, nginx, apache2, node, uvicorn, gunicorn]
  shell_names: [sh, bash, nc, python, perl, curl, wget]

alerts:
  stdout: true
  # webhooks receive a JSON document like the log line you see above:
  # {"source":"uplert","rule":"php_in_media","level":"critical","path":"..."}
  webhook: https://hooks.example.com/uplert
  telegram_bot_token: "123456:AA..."
  telegram_chat_id: "42"
```

`UPLERT_LOG_LEVEL` env var overrides `log_level`.

## Rules reference

| Rule | Level | What it catches |
|---|---|---|
| `dangerous_extension` | high | `.php`, `.phtml`, `.phar`, `.py`, `.jsp`, … |
| `double_extension` | high | `image.php.jpg` (script ext not at the end) |
| `executable_in_uploads` | high | any file where x-bit is set |
| `php_in_media` | critical | `<?php`, `eval(`, `$_POST`… inside `.png/.jpg/...` incl. tail of big files |
| `script_in_html_or_svg` | high | `<script`, `onload=`, `javascript:` |
| `suspicious_web_config` | critical | `php_value`, `auto_prepend_file` in `.htaccess`/`.user.ini`/`web.config` |
| `magic_mismatch` | medium | the file claims `.jpg` but is not a JPEG |
| `shebang_in_watched_dir` | medium | `#!/bin/...` in any file |
| `exec_from_watch_dir` | critical | a process whose binary came from a watched dir |
| `web_spawned_shell` | critical | php-fpm/node spawning `sh`, `nc`, `curl`, … |

### Response engine

```text
finding level ≥ critical → (dry_run? log-only : SIGTERM, 3s grace, SIGKILL)
```

`dry_run: true` never kills anything — it only logs what *would* happen. Set
`dry_run: false` **only** after watching the dry-run output for a few days.
Uplert refuses to kill PID 1 and itself.

## Benchmark (idle VPS, watcher + fallback scan every 60 s)

```text
$ ls -l bin/uplert  →  8.6 MB  (static, CGO_ENABLED=0)
$ grep VmRSS /proc/$(pidof uplert)/status
VmRSS: 12800 kB
```

## Deploy

### systemd

```bash
sudo cp deploy/uplert.service /etc/systemd/system/uplert.service
sudo systemctl daemon-reload
sudo systemctl enable --now uplert
journalctl -u uplert -f
```

### Docker

```bash
make build
docker build -t uplert:latest .
docker run --rm -v $(pwd)/uploads:/etc/uplert/uploads:ro uplert:latest run
```

## Development

```bash
make test        # tests with -race
make fmt vet
make build
make test-agent  # generate harmless test files in ./test_uploads
```

CI runs fmt + vet + race tests + static build on every push.

## Roadmap

- [ ] rule cooldowns and per-folder allowlists (`known-upload-hashes.json`)
- [ ] entropy scoring for obfuscated payloads
- [ ] container-aware process trees (`--docker` label match)
- [ ] HTTP-based rule and fan-out metrics (`/metrics` for Prometheus)
- [ ] one binary per target: `make release` (tar.gz amd64/arm64)

## Known limitations

- Does not prevent exploitation — detects aftermath.
- Inotify watches are per directory; enormous trees need higher limits
  (`fs.inotify.max_user_watches`).
- Polling-based process detection may miss sub-second shell spawn. The file
  layer (upload detection) covers those cases as the primary defence.
- Content rules are heuristic. Reduce false positives via ignore lists and
  level filtering; report FP examples in issues, they read the README.

## Why a Go binary of 8 MB?

Because VPS users run fastapi/next.js/php-fpm behind nginx with 512 MB of RAM.
Uplert is designed to be negligible — leaving the job of heavy duty checks
to bigger tools, if and when you hire them.

## License

MIT © [pbadev](https://github.com/pbadev)
