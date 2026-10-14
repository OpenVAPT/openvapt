#!/bin/sh
# OpenVAPT one-command installer.
#
# Download Only (the default): install and verify, scan nothing.
#   curl -fsSL https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh | sh
# Download and Scan: install, verify, then scan THIS machine and write every report.
#   curl -fsSL https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh | sh -s -- --run
#
# What it does, in order (read it before running it):
#   1. Checks this is Linux on amd64 or arm64.
#   2. Reads the public channel list and picks the most stable channel that
#      has a release (stable, then rc, then beta, then alpha), warning you
#      when that is a pre-release; or uses --channel NAME or --version vX.Y.Z.
#   3. Downloads the binary and SHA256SUMS from GitHub Releases over HTTPS.
#   4. Verifies the SHA-256 checksum (always) and the Sigstore signature
#      (when cosign is installed). Any mismatch stops the install.
#   5. Installs the binary to ~/.local/bin (or /usr/local/bin as root).
#   6. With --run only: starts a read-only scan of THIS machine. The scan
#      shows the acknowledgements and waits for you to type I ACCEPT on the
#      terminal; the installer never accepts for you. Reports (html, json,
#      sarif, md, signed) go to ~/openvapt-reports/<UTC time>/ (mode 0700).
#
# It scans nothing unless you pass --run. It sends nothing anywhere except
# the downloads from GitHub, stores nothing except the binary and, with
# --run, the reports and the report signing key, and needs no root unless
# you choose a system folder or --sudo (which applies to the scan only).
# Downloads come from GitHub, a third party. This script is part of OpenVAPT:
# provided free, as is, with no warranty, and run 100% at your own risk under
# the EULA and the OpenVAPT Source-Available Licence 1.3 (own use only).
#
# Options:
#   --channel NAME     stable, rc, beta or alpha (default: the most stable one with a release)
#   --version vX.Y.Z   install this exact release instead
#   --dir DIR          install into DIR (default ~/.local/bin, or /usr/local/bin as root)
#   --run              Download and Scan: after installing, scan THIS machine interactively
#   --sudo             with --run: run only the scan with sudo, for full coverage
#   --out DIR          with --run: write the reports into DIR (must not exist yet)
#   --open             with --run: open report.html with xdg-open, only in a desktop session
#   --dry-run          after installing, preview what a scan would read and run; scan nothing
#   --help             show this help
# Environment: OPENVAPT_CHANNEL, OPENVAPT_VERSION, OPENVAPT_INSTALL_DIR, OPENVAPT_BASE_URL
# (releases location) and OPENVAPT_CHANNELS_URL (channel list location), for mirrors and tests.
# OPENVAPT_REQUIRE_SIGNATURE=1 refuses to install unless cosign verifies the Sigstore signature.
# OPENVAPT_ALLOW_FILE=1 permits file:// locations (offline tests only); otherwise HTTPS only.
# OPENVAPT_TEST_ANY_OS=1, honoured only with OPENVAPT_ALLOW_FILE=1, skips the Linux check so
# the installer's own tests can run on a developer's machine.

# Everything runs inside main, called on the last line, so a partially
# downloaded script does nothing at all.
set -eu

REPO_URL="https://github.com/OpenVAPT/openvapt"
# Only the release workflow on main may have signed a release.
SIGNER='^https://github\.com/OpenVAPT/openvapt/\.github/workflows/release\.yml@refs/heads/main$'
ISSUER="https://token.actions.githubusercontent.com"

say() { printf '%s\n' "$*"; }
err() { printf 'openvapt-install: %s\n' "$*" >&2; }
die() {
	err "$*"
	exit 1
}

# usage is a copy of the header, so --help also works when piped into sh.
usage() {
	cat <<'EOF_USAGE'
OpenVAPT one-command installer

Download Only (the default): install and verify, scan nothing.
  curl -fsSL https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh | sh
Download and Scan: install, verify, then scan THIS machine and write every report.
  curl -fsSL https://raw.githubusercontent.com/OpenVAPT/openvapt/main/scripts/install.sh | sh -s -- --run

Options:
  --channel NAME     stable, rc, beta or alpha (default: the most stable one with a release)
  --version vX.Y.Z   install this exact release instead
  --dir DIR          install into DIR (default ~/.local/bin, or /usr/local/bin as root)
  --run              Download and Scan: after installing, scan THIS machine interactively
  --sudo             with --run: run only the scan with sudo, for full coverage
  --out DIR          with --run: write the reports into DIR (must not exist yet)
  --open             with --run: open report.html with xdg-open, only in a desktop session
  --dry-run          after installing, preview what a scan would read and run; scan nothing
  --help             show this help

It verifies the SHA-256 checksum (always) and the Sigstore signature (when
cosign is installed). It scans nothing unless you pass --run, and the scan
always shows the acknowledgements and waits for you to type I ACCEPT on the
terminal; the installer never accepts for you. Reports go to
~/openvapt-reports/<UTC time>/ unless you pass --out. Provided free, as is,
100% at your own risk.
EOF_USAGE
}

fetch() { # fetch URL FILE
	# HTTPS only, also across redirects. file:// is accepted only when
	# OPENVAPT_ALLOW_FILE=1, for the installer's own offline tests.
	case "$1" in
	https://*) ;;
	file://*) [ "${OPENVAPT_ALLOW_FILE:-0}" = 1 ] || die "file:// URLs need OPENVAPT_ALLOW_FILE=1 (tests only)" ;;
	*) die "refusing a non-HTTPS URL" ;;
	esac
	if command -v curl >/dev/null 2>&1; then
		if [ "${OPENVAPT_ALLOW_FILE:-0}" = 1 ]; then
			curl -fsSL --proto '=https,file' --proto-redir '=https' --tlsv1.2 --retry 2 -o "$2" "$1"
		else
			curl -fsSL --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 2 -o "$2" "$1"
		fi
	elif command -v wget >/dev/null 2>&1; then
		case "$1" in
		https://*) wget -q --https-only --secure-protocol=TLSv1_2 --max-redirect=5 -O "$2" "$1" ;;
		*) die "wget can fetch only https:// URLs; install curl for file:// tests" ;;
		esac
	else
		die "curl or wget is required"
	fi
}

# check_url NAME URL refuses, with a clear reason, any download location that
# is not https:// (file:// only with OPENVAPT_ALLOW_FILE=1, for tests). It runs
# before any download, so the reason is never hidden by a quiet fetch.
check_url() {
	case "$2" in
	https://*) return 0 ;;
	file://*) [ "${OPENVAPT_ALLOW_FILE:-0}" = 1 ] && return 0 ;;
	esac
	safe=$(printf '%s' "$2" | cut -d: -f1 | tr -cd 'A-Za-z0-9+.-' | cut -c1-20)
	die "$1 must be an https:// URL (got a ${safe:-scheme-less} URL). Refusing to download over anything but HTTPS."
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

# fetch_channels downloads the public channel list (release/channels.txt in
# the repository: "<channel> <version> <commit> <date>" per line) once.
fetch_channels() {
	[ -s "$TMP/channels.txt" ] && return 0
	fetch "$CHANNELS_URL" "$TMP/channels.raw" 2>/dev/null || return 1
	tr -d '\r' <"$TMP/channels.raw" >"$TMP/channels.txt"
}

# channel_version prints the version currently published in a channel, or nothing.
channel_version() {
	case "$1" in
	stable | rc | beta | alpha) ;;
	*) return 0 ;;
	esac
	[ -s "$TMP/channels.txt" ] || return 0
	awk -v c="$1" '!/^#/ && $1 == c && $2 ~ /^v/ { print $2; exit }' "$TMP/channels.txt"
}

channel_name() {
	case "$1" in
	stable) printf 'Stable' ;;
	rc) printf 'Release Candidate' ;;
	beta) printf 'Beta' ;;
	alpha) printf 'Alpha' ;;
	esac
}

# choose_release sets VERSION and CHANNEL. A forced channel must have a
# release; otherwise the most stable channel that has one is used.
choose_release() {
	if ! fetch_channels; then
		die "cannot read the channel list from $CHANNELS_URL. Try again, or choose a release with --version vX.Y.Z"
	fi
	avail=$(awk '!/^#/ && NF >= 2 && $1 ~ /^(stable|rc|beta|alpha)$/ { printf "%s%s %s", sep, $1, $2; sep=", " }' "$TMP/channels.txt")
	[ -n "$avail" ] || avail="none yet"
	if [ -n "$CHANNEL" ]; then
		VERSION=$(channel_version "$CHANNEL")
		[ -n "$VERSION" ] || die "no $CHANNEL release is published (channels with a release: $avail). Choose another with --channel, or build from source: $REPO_URL#build-from-source"
		return 0
	fi
	for c in stable rc beta alpha; do
		VERSION=$(channel_version "$c")
		if [ -n "$VERSION" ]; then
			CHANNEL=$c
			break
		fi
	done
	[ -n "$VERSION" ] || die "no release is published in any channel yet. Build from source instead: $REPO_URL#build-from-source"
	if [ "$CHANNEL" != stable ]; then
		say "  WARNING: there is no Stable release yet, so this installs the newest pre-release,"
		say "  from the $(channel_name "$CHANNEL") channel ($VERSION). Pre-releases may be incomplete or wrong."
		say "  Use it only on a test machine you own or control, 100% at your own risk."
	fi
}

has_tty() {
	# Readable is not enough: in CI and cron /dev/tty exists but cannot be opened.
	(: </dev/tty) 2>/dev/null
}

main() {
	VERSION="${OPENVAPT_VERSION:-}"
	CHANNEL="${OPENVAPT_CHANNEL:-}"
	CHANNELS_URL="${OPENVAPT_CHANNELS_URL:-https://raw.githubusercontent.com/OpenVAPT/openvapt/main/release/channels.txt}"
	DIR="${OPENVAPT_INSTALL_DIR:-}"
	BASE_URL="${OPENVAPT_BASE_URL:-$REPO_URL/releases}"
	RUN=0
	SUDO=0
	OPEN=0
	DRY=0
	OUT=""
	while [ $# -gt 0 ]; do
		case "$1" in
		--version) [ $# -ge 2 ] || die "--version needs a value"; VERSION="$2"; shift 2 ;;
		--channel) [ $# -ge 2 ] || die "--channel needs a value"; CHANNEL="$2"; shift 2 ;;
		--dir) [ $# -ge 2 ] || die "--dir needs a value"; DIR="$2"; shift 2 ;;
		--out) [ $# -ge 2 ] || die "--out needs a value"; OUT="$2"; shift 2 ;;
		--run) RUN=1; shift ;;
		--sudo) SUDO=1; shift ;;
		--open) OPEN=1; shift ;;
		--dry-run) DRY=1; shift ;;
		-h | --help) usage; exit 0 ;;
		*) die "unknown option: $1 (try --help)" ;;
		esac
	done
	if [ "$RUN" -eq 0 ]; then
		[ "$SUDO" -eq 0 ] || die "--sudo applies only to the scan; add --run (Download and Scan)"
		[ -z "$OUT" ] || die "--out applies only to the scan; add --run (Download and Scan)"
		[ "$OPEN" -eq 0 ] || die "--open applies only to the scan; add --run (Download and Scan)"
	fi
	case "$OUT" in
	"" | /*) ;;
	*) OUT="$(pwd)/$OUT" ;;
	esac

	OS=$(uname -s)
	if [ "${OPENVAPT_TEST_ANY_OS:-0}" = 1 ] && [ "${OPENVAPT_ALLOW_FILE:-0}" = 1 ]; then
		OS=Linux
	fi
	case "$OS" in
	Linux) ;;
	*) die "OpenVAPT runs on Linux only. On other systems, read the code or try 'openvapt demo' after building from source: $REPO_URL" ;;
	esac
	case "$(uname -m)" in
	x86_64 | amd64) ARCH=amd64 ;;
	aarch64 | arm64) ARCH=arm64 ;;
	*) die "unsupported CPU $(uname -m); build from source: $REPO_URL" ;;
	esac

	case "$CHANNEL" in
	"" | stable | rc | beta | alpha) ;;
	*) die "--channel must be stable, rc, beta or alpha, got: $CHANNEL" ;;
	esac

	TMP=$(mktemp -d 2>/dev/null || mktemp -d -t openvapt)
	trap 'rm -rf "$TMP"' EXIT
	trap 'exit 130' INT TERM

	say "OpenVAPT installer"
	check_url OPENVAPT_CHANNELS_URL "$CHANNELS_URL"
	check_url OPENVAPT_BASE_URL "$BASE_URL"
	if [ -z "$VERSION" ]; then
		choose_release
	fi
	if ! printf '%s\n' "$VERSION" | grep -Eq '^v[0-9]+\.[0-9]+\.[0-9]+(-(alpha|beta|rc)\.[0-9]+)?$'; then
		safe=$(printf '%s' "$VERSION" | tr -cd 'A-Za-z0-9._-' | cut -c1-40)
		die "version must look like v1.2.3 or v1.2.3-rc.1, got: $safe"
	fi

	if [ -z "$DIR" ]; then
		if [ "$(id -u)" -eq 0 ]; then
			DIR=/usr/local/bin
		else
			[ -n "${HOME:-}" ] || die "HOME is not set; choose a folder with --dir"
			DIR="$HOME/.local/bin"
		fi
	fi

	BIN="openvapt_linux_$ARCH"

	say "  release $VERSION, linux/$ARCH"
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
			--certificate-github-workflow-repository OpenVAPT/openvapt \
			--bundle "$TMP/$BIN.sigstore.json" "$TMP/$BIN" >/dev/null 2>&1 ||
			die "Sigstore signature verification failed for $BIN. Nothing was installed."
		say "  Sigstore signature verified (built by the OpenVAPT GitHub release workflow)"
	elif [ "${OPENVAPT_REQUIRE_SIGNATURE:-0}" = 1 ]; then
		die "OPENVAPT_REQUIRE_SIGNATURE=1 but cosign is not installed, so the Sigstore signature cannot be checked. Nothing was installed."
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

	if [ "$DRY" -eq 1 ]; then
		say ""
		say "Dry run: previewing every file, command and request a scan would use. Nothing is scanned."
		"$DIR/openvapt" scan --dry-run || die "the dry run did not complete"
		say ""
		say "Dry run finished. Nothing was scanned and no report was written."
		return 0
	fi

	if [ "$RUN" -eq 0 ]; then
		next_steps
		return 0
	fi
	run_scan
}

# next_steps is the Download Only ending: what was done and what to run next.
next_steps() {
	say ""
	say "Installed (Download Only). Nothing has been scanned. OpenVAPT checks only this machine,"
	say "read-only, and before every scan it shows the acknowledgements and waits for you to type I ACCEPT."
	say "Next steps, when you are ready:"
	say "  $CMD terms              read the acknowledgements"
	say "  $CMD scan --dry-run     preview every file, command and request a scan would use"
	say "  sudo $CMD scan          scan this machine (only one you own or control) with full coverage"
	say "  $CMD scan               or scan without root (some checks are Incomplete)"
	case "$VERSION" in
	v0.1.0-alpha.[123])
		# Releases before v0.1.0-alpha.4 have no default reports folder.
		say "Reports: $VERSION writes a new folder openvapt-report-<time> in the folder you run the scan"
		say "from; choose one with --out DIR, for example: sudo $CMD scan --out ~/openvapt-report"
		say "(openvapt-reports/<UTC time>/ in your home folder is the default from the next release)." ;;
	*)
		say "Reports: a new folder ~/openvapt-reports/<UTC time>/ in the home folder of the user who runs"
		say "the scan, holding report.html, report.json, report.sarif and report.md, readable only by that"
		say "user. With sudo it is the home folder sudo sets (usually root's); when sudo keeps your HOME,"
		say "the folder is given back to you. Add --out DIR to choose another folder." ;;
	esac
	say "Uninstall: rm $DIR/openvapt"
}

# summary_line prints the severity counts from report.json.
summary_line() {
	[ -r "$1" ] || return 0
	awk '
		/"summary"[ ]*:[ ]*\{/ { in_s = 1; next }
		in_s && /\}/ { in_s = 0 }
		in_s {
			line = $0; gsub(/[",]/, "", line); split(line, kv, ":")
			k = kv[1]; gsub(/ /, "", k); v = kv[2]; gsub(/ /, "", v); n[k] = v
		}
		END {
			if ("critical" in n)
				printf "Summary: Critical %s, High %s, Medium %s, Low %s, Passed %s, Incomplete %s, Errors %s\n", n["critical"], n["high"], n["medium"], n["low"], n["passed"], n["incomplete"], n["errors"]
		}' "$1"
}

exit_meaning() {
	case "$1" in
	0) printf 'completed: no finding at or above High and no coverage gap' ;;
	2) printf 'invalid arguments or usage' ;;
	3) printf 'findings at or above High severity were found' ;;
	4) printf 'incomplete coverage: some checks could not observe enough to decide' ;;
	5) printf 'internal error, a check error, the terms were not accepted, or the scan was interrupted' ;;
	6) printf 'the report could not be written' ;;
	*) printf 'unexpected exit code' ;;
	esac
}

# run_scan is the Download and Scan ending. The scan itself shows the
# acknowledgements and reads I ACCEPT from the terminal; this function never
# passes --accept-terms on your behalf.
run_scan() {
	has_tty || die "--run needs an interactive terminal to type I ACCEPT, and none is available. Nothing was scanned. Run '$CMD scan' yourself in a terminal."
	if [ -z "$OUT" ]; then
		[ -n "${HOME:-}" ] || die "HOME is not set, so there is nowhere to write the reports; add --out DIR"
		stamp=$(date -u +%Y%m%dT%H%M%SZ)
		OUT="$HOME/openvapt-reports/$stamp"
		n=2
		while [ -e "$OUT" ]; do
			OUT="$HOME/openvapt-reports/$stamp-$n"
			n=$((n + 1))
		done
	fi
	[ ! -e "$OUT" ] || die "$OUT already exists; reports are never written over. Choose a new folder with --out"
	parent=$(dirname "$OUT")
	(umask 077 && mkdir -p "$parent") || die "cannot create $parent"

	SCAN_AS=user
	if [ "$SUDO" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
		command -v sudo >/dev/null 2>&1 || die "--sudo was given but sudo is not installed. Nothing was scanned."
		SCAN_AS=sudo
	fi

	say ""
	say "Download and Scan: starting a read-only scan of THIS machine only (127.0.0.1)."
	say "Scan only a machine you own or control. Next, OpenVAPT shows the acknowledgements;"
	say "type I ACCEPT to scan, or anything else to cancel. The installer does not answer for you."
	if [ "$SCAN_AS" = sudo ]; then
		say "Why sudo: as root, checks can read protected files such as /etc/shadow and sudo rules."
		say "Only the scan runs with sudo; the install above did not. sudo may ask for your password."
	elif [ "$(id -u)" -ne 0 ]; then
		say "Running as $(id -un) without root: checks that need protected files are reported as"
		say "Incomplete. For full coverage, rerun with --run --sudo."
	fi
	say "Reports folder: $OUT"
	say "This usually takes one to five minutes."

	status=0
	if [ "$SCAN_AS" = sudo ]; then
		# The terminal is opened by this user on purpose: the scan reads I ACCEPT from it.
		# shellcheck disable=SC2024
		sudo "$DIR/openvapt" scan --out "$OUT" --format html,json,sarif,md </dev/tty || status=$?
		if [ -d "$OUT" ]; then
			sudo chown -R "$(id -u):$(id -g)" "$OUT" 2>/dev/null || err "could not give $OUT back to $(id -un); it belongs to root"
		fi
	else
		"$DIR/openvapt" scan --out "$OUT" --format html,json,sarif,md </dev/tty || status=$?
	fi

	say ""
	if [ ! -s "$OUT/report.json" ]; then
		err "no report was written (exit code $status: $(exit_meaning "$status"))."
		return "$status"
	fi
	say "Scan finished."
	summary_line "$OUT/report.json"
	say "Exit code $status: $(exit_meaning "$status")"
	say "Reports (only on this machine, readable only by you):"
	for f in "$OUT"/report.html "$OUT"/report.json "$OUT"/report.sarif "$OUT"/report.md; do
		[ -e "$f" ] && say "  $f"
	done
	say "Open the HTML report in any web browser, for example: xdg-open $OUT/report.html"
	say "Check its signature later with: $CMD verify $OUT/report.json"
	if [ "$OPEN" -eq 1 ]; then
		if [ -z "${DISPLAY:-}" ] && [ -z "${WAYLAND_DISPLAY:-}" ]; then
			say "--open: no desktop session (DISPLAY or WAYLAND_DISPLAY is not set), so nothing was opened."
		elif ! command -v xdg-open >/dev/null 2>&1; then
			say "--open: xdg-open is not installed, so nothing was opened."
		elif [ "$(id -u)" -eq 0 ]; then
			say "--open: not starting a web browser as root."
		else
			xdg-open "$OUT/report.html" >/dev/null 2>&1 || say "--open: xdg-open did not succeed; open the file yourself."
		fi
	fi
	case "$status" in
	0 | 3 | 4) return 0 ;;
	*) return "$status" ;;
	esac
}

main "$@"
