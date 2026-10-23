#!/bin/sh
# Uplert installer: downloads the latest release binary.
set -eu

REPO="pbadev/Uplert"
BINDIR="/usr/local/bin"
CONFDIR="/etc/uplert"

command -v curl >/dev/null 2>&1 || {
	echo "curl is required" >&2
	exit 1
}

OS=$(uname -s)
ARCH=$(uname -m)

case "$OS" in
Linux) OS="linux" ;;
*) echo "unsupported OS: $OS" >&2; exit 1 ;;
esac

case "$ARCH" in
x86_64) ARCH="amd64" ;;
aarch64 | arm64) ARCH="arm64" ;;
*) echo "unsupported arch: $ARCH" >&2; exit 1 ;;
esac

echo "[-] fetching latest release meta..."
URL=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" |
	grep -o "https://[^\"]*/uplert_${OS}_${ARCH}\.tar\.gz" |
	head -n1)

[ -n "$URL" ] || {
	echo "no release asset found" >&2
	exit 1
}

echo "[-] downloading $URL"
curl -fsSL "$URL" | tar -xz uplert

sudo -n true 2>/dev/null || SUDO=""
[ "$(id -u)" -eq 0 ] && SUDO=""

echo "[-] installing to ${BINDIR}"
${SUDO:+sudo} mv uplert "${BINDIR}/uplert"
${SUDO:+sudo} chmod 0755 "${BINDIR}/uplert"

if [ ! -f "${CONFDIR}/config.yaml" ]; then
	echo "[-] installing default config to ${CONFDIR}"
	${SUDO:+sudo} mkdir -p "${CONFDIR}"
	echo "    please edit ${CONFDIR}/config.yaml"
fi

echo "[-] installed: $(${BINDIR}/uplert --version 2>/dev/null || echo uplert)"
echo "    next: edit ${CONFDIR}/config.yaml, then: systemd enable uplert"
