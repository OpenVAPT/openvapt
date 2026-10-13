#!/bin/sh
# OpenVAPT one-command installer.
#
#   curl -fsSL https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh | sh
#
# What it does, in order (read it before running it):
#   1. Checks this is Linux on amd64 or arm64.
#   2. Finds the release of the chosen channel (Stable by default) from the
#      public channel list, or uses --version vX.Y.Z.
#   3. Downloads the binary and SHA256SUMS from GitHub Releases.
#   4. Verifies the SHA-256 checksum (always) and the Sigstore signature
#      (when cosign is installed). Any mismatch stops the install.
#   5. Installs the binary to ~/.local/bin (or /usr/local/bin as root).
#
# It is designed never to scan anything unless you pass --run, and even then the scan asks
# you to read the acknowledgements and type I ACCEPT, as every scan does.
# It sends nothing anywhere except the downloads from GitHub, stores nothing
# except the binary, and needs no root unless you choose a system folder.
# Downloads come from GitHub, a third party. This script is part of OpenVAPT:
# provided free, as is, with no warranty, and run 100% at your own risk under
# the EULA and the OpenVAPT Source-Available Licence 1.0 (own use only).
#
# Options:
#   --channel NAME     stable (default), rc, beta or alpha; pre-releases may be wrong
#   --version vX.Y.Z   install this exact release instead
#   --dir DIR          install into DIR
#   --run              after installing, start an interactive scan of THIS machine
#   --help             show this help
# Environment: OPENVAPT_CHANNEL, OPENVAPT_VERSION, OPENVAPT_INSTALL_DIR, OPENVAPT_BASE_URL
# (releases location) and OPENVAPT_CHANNELS_URL (channel list location), for mirrors and tests.

# Everything runs inside main, called on the last line, so a partially
# downloaded script does nothing at all.
set -eu

REPO_URL="https://github.com/OpenVAPT/openvapt"
SIGNER="^https://github.com/OpenVAPT/openvapt/"
ISSUER="https://token.actions.githubusercontent.com"

say() { printf '%s\n' "$*"; }
err() { printf 'openvapt-install: %s\n' "$*" >&2; }
die() {
	err "$*"
	exit 1
}

usage() { sed -n '2,/^$/p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//' || true; }

fetch() { # fetch URL FILE
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --proto '=https,file' --tlsv1.2 --retry 2 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q --https-only -O "$2" "$1"
	else
		die "curl or wget is required"
	fi
}

sha256() { # sha256 FILE -> hex digest
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | cut -d' ' -f1
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | cut -d' ' -f1
	else
		die "sha256sum or shasum is required to verify the download"
	fi
}

# channel_version reads the public channel list (release/channels.txt in
# the repository: "<channel> <version> <commit> <date>" per line) and prints
# the version currently published in the requested channel, or nothing.
channel_version() {
	list="$TMP/channels.txt"
	fetch "$CHANNELS_URL" "$list" 2>/dev/null || return 0
	awk -v c="$1" '$1 == c { print $2; exit }' "$list"
}

main() {
	VERSION="${OPENVAPT_VERSION:-}"
	CHANNEL="${OPENVAPT_CHANNEL:-stable}"
	CHANNELS_URL="${OPENVAPT_CHANNELS_URL:-https://raw.githubusercontent.com/OpenVAPT/openvapt/main/release/channels.txt}"
	DIR="${OPENVAPT_INSTALL_DIR:-}"
	BASE_URL="${OPENVAPT_BASE_URL:-$REPO_URL/releases}"
	RUN=0
	while [ $# -gt 0 ]; do
		case "$1" in
		--version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
		--channel) [ $# -ge 2 ] || die "--channel needs a value"; CHANNEL="$2"; shift 2 ;;
		--dir) [ $# -ge 2 ] || die "--dir needs a value"; DIR="$2"; shift 2 ;;
		--run) RUN=1; shift ;;
		-h | --help) usage; exit 0 ;;
		*) die "unknown option: $1 (try --help)" ;;
		esac
	done

	case "$(uname -s)" in
	Linux) ;;
	*) die "OpenVAPT runs on Linux only. On other systems, read the code or try 'openvapt demo' after building from source: $REPO_URL" ;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) ARCH=amd64 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	*) die "unsupported CPU $(uname -m); build from source: $REPO_URL" ;;
	esac

	case "$CHANNEL" in
	stable | rc | beta | alpha) ;;
	*) die "--channel must be stable, rc, beta or alpha, got: $CHANNEL" ;;
	esac

	TMP=$(mktemp -d 2>/dev/null || mktemp -d -t openvapt)
	trap 'rm -rf "$TMP"' EXIT INT TERM

	if [ -z "$VERSION" ]; then
		VERSION=$(channel_version "$CHANNEL")
		if [ -z "$VERSION" ]; then
			avail=$(awk '!/^#/ && NF { printf "%s%s", sep, $1; sep=", " }' "$TMP/channels.txt" 2>/dev/null || true)
			[ -n "$avail" ] || avail="none yet"
			die "no $CHANNEL release is published (channels with a release: $avail). Choose one with --channel, or build from source: $REPO_URL#build-from-source"
		fi
	fi
	case "$VERSION" in
	v[0-9]*) ;;
	*) die "version must look like v1.2.3, got: $VERSION" ;;
	esac
	case "$VERSION" in
	*[!A-Za-z0-9._-]*) die "version contains unexpected characters: $VERSION" ;;
	esac

	if [ -z "$DIR" ]; then
		if [ "$(id -u)" -eq 0 ]; then DIR=/usr/local/bin; else DIR="$HOME/.local/bin"; fi
	fi

	BIN="openvapt_linux_$ARCH"

	say "OpenVAPT installer: release $VERSION, linux/$ARCH"
	case "$VERSION" in
	*-alpha.* | *-beta.* | *-rc.*)
		say "  WARNING: $VERSION is a pre-release. It may be incomplete or wrong; use it only on test machines, 100% at your own risk." ;;
	esac
	say "  downloading $BIN and SHA256SUMS from $BASE_URL/download/$VERSION/"
	fetch "$BASE_URL/download/$VERSION/$BIN" "$TMP/$BIN" || die "download failed: $BIN"
	fetch "$BASE_URL/download/$VERSION/SHA256SUMS" "$TMP/SHA256SUMS" || die "download failed: SHA256SUMS"

	want=$(awk -v f="$BIN" '$2 == f || $2 == "*" f { print $1; exit }' "$TMP/SHA256SUMS")
	[ -n "$want" ] || die "SHA256SUMS has no entry for $BIN"
	got=$(sha256 "$TMP/$BIN")
	[ "$got" = "$want" ] || die "checksum mismatch for $BIN (expected $want, got $got). Nothing was installed."
	say "  checksum verified (sha256 $got)"

	if command -v cosign >/dev/null 2>&1; then
		fetch "$BASE_URL/download/$VERSION/$BIN.sigstore.json" "$TMP/$BIN.sigstore.json" || die "download failed: Sigstore bundle"
		cosign verify-blob --certificate-identity-regexp "$SIGNER" --certificate-oidc-issuer "$ISSUER" \
			--bundle "$TMP/$BIN.sigstore.json" "$TMP/$BIN" >/dev/null 2>&1 ||
			die "Sigstore signature verification failed for $BIN. Nothing was installed."
		say "  Sigstore signature verified (built by the OpenVAPT GitHub release workflow)"
	else
		say "  note: cosign is not installed, so the Sigstore signature was not checked."
		say "        The checksum came from the same release. For a second, independent check see $REPO_URL#verify"
	fi

	mkdir -p "$DIR" || die "cannot create $DIR (choose another with --dir)"
	cp "$TMP/$BIN" "$DIR/.openvapt.new" || die "cannot write to $DIR (choose another with --dir)"
	chmod 0755 "$DIR/.openvapt.new"
	mv -f "$DIR/.openvapt.new" "$DIR/openvapt"
	say "  installed $DIR/openvapt"
	"$DIR/openvapt" version || die "the installed binary did not run"

	case ":$PATH:" in
	*":$DIR:"*) CMD=openvapt ;;
	*)
		CMD="$DIR/openvapt"
		say ""
		say "  $DIR is not on your PATH. Add it with:  export PATH=\"$DIR:\$PATH\""
		;;
	esac

	say ""
	say "Installed. Nothing has been scanned. OpenVAPT checks only this machine, read-only,"
	say "and before every scan it shows the acknowledgements and waits for you to type I ACCEPT."
	say "Next steps:"
	say "  $CMD terms              read the acknowledgements"
	say "  $CMD demo               try it on a simulated server, in memory"
	say "  $CMD scan --dry-run     preview every file, command and request a scan would use"
	say "  sudo $CMD scan --out ~/openvapt-report   scan this machine (only one you own or control)"
	say "Uninstall: rm $DIR/openvapt"

	[ "$RUN" -eq 1 ] || return 0
	run_scan
}

# run_scan starts an interactive scan of this machine. The scan itself shows
# the acknowledgements and requires I ACCEPT; this function never passes
# --accept-terms on your behalf.
run_scan() {
	[ -r /dev/tty ] || die "--run needs an interactive terminal; run: sudo $DIR/openvapt scan --out ~/openvapt-report"
	OUT="$HOME/openvapt-report-$(date +%Y%m%d-%H%M%S)"
	say ""
	say "Starting a read-only scan of THIS machine only. Scan only a machine you own or control."
	say "Report folder: $OUT"
	status=0
	if [ "$(id -u)" -eq 0 ]; then
		"$DIR/openvapt" scan --out "$OUT" </dev/tty || status=$?
	elif command -v sudo >/dev/null 2>&1; then
		say "Running with sudo so checks can read protected files such as /etc/shadow."
		# The terminal is opened by this user on purpose: the scan reads I ACCEPT from it.
		# shellcheck disable=SC2024
		sudo "$DIR/openvapt" scan --out "$OUT" </dev/tty || status=$?
		if [ -d "$OUT" ]; then
			sudo chown -R "$(id -u):$(id -g)" "$OUT" 2>/dev/null || true
		fi
	else
		say "sudo is not available; scanning without root, so some checks will be skipped or Incomplete."
		"$DIR/openvapt" scan --out "$OUT" </dev/tty || status=$?
	fi
	case "$status" in
	0) say "Scan finished. Open $OUT/report.html" ;;
	3) say "Scan finished with Critical or High findings. Open $OUT/report.html" ;;
	4) say "Scan finished with incomplete coverage. Open $OUT/report.html" ;;
	*) err "the scan ended with exit code $status (see 'openvapt scan --help')"; return "$status" ;;
	esac
}

main "$@"
