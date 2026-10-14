#!/bin/sh
# End-to-end test of scripts/install.sh against a fake local release served
# from file:// (OPENVAPT_ALLOW_FILE=1). It covers: file:// refused without the
# test switch, channel fallback, a forced channel without a release, Download
# Only output, --run refused without a terminal, Download and Scan in a
# scripted terminal (accepting, and cancelling), --out, --dry-run, option
# errors and refusal of a bad checksum.
#
#   sh scripts/test-install.sh PATH/TO/openvapt
#
# PATH/TO/openvapt must run on this machine (in CI: dist/release/openvapt_linux_amd64).
# This test never scans a real machine. The --run cases install a test double
# that prints the real acknowledgements (openvapt terms), reads the answer from
# the terminal exactly as a scan does, and then scans only the simulated lab
# held in memory (openvapt demo), writing every report format.
set -eu

if [ $# -ne 1 ] || [ ! -x "$1" ]; then
	echo "usage: sh scripts/test-install.sh PATH/TO/openvapt" >&2
	exit 2
fi
ROOT=$(cd "$(dirname "$0")/.." && pwd)
W=$(mktemp -d 2>/dev/null || mktemp -d -t ovtest)
trap 'rm -rf "$W"' EXIT
cp "$ROOT/scripts/install.sh" "$W/install.sh"
cp "$1" "$W/real-openvapt"
chmod 0755 "$W/real-openvapt"

case "$(uname -m)" in
x86_64 | amd64) A=amd64 ;;
aarch64 | arm64) A=arm64 ;;
*) echo "unsupported CPU" >&2; exit 2 ;;
esac
B="openvapt_linux_$A"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok:   $*"; }
sha() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
release() { # release VERSION FILE
	d="$W/rel/download/$1"
	mkdir -p "$d"
	cp "$2" "$d/$B"
	chmod 0755 "$d/$B"
	printf '%s  %s\n' "$(sha "$d/$B")" "$B" >"$d/SHA256SUMS"
}

# v0.0.0-alpha.1: the real binary. v0.0.0-alpha.2: the scan test double.
release v0.0.0-alpha.1 "$W/real-openvapt"
cat >"$W/double" <<EOD
#!/bin/sh
# Test double for the installer test: never scans this machine.
real="$W/real-openvapt"
if [ "\${1:-}" = scan ]; then
	shift
	for a in "\$@"; do [ "\$a" = --dry-run ] && exec "\$real" scan "\$@"; done
	"\$real" terms
	printf 'type I ACCEPT to continue (anything else cancels; nothing is stored): '
	read -r answer || answer=
	[ "\$answer" = "I ACCEPT" ] || { echo "openvapt: terms not accepted; nothing was scanned" >&2; exit 5; }
	exec "\$real" demo "\$@"
fi
exec "\$real" "\$@"
EOD
release v0.0.0-alpha.2 "$W/double"

printf '# test channels\nalpha v0.0.0-alpha.1 0 2026-10-14\n' >"$W/channels.txt"
export OPENVAPT_BASE_URL="file://$W/rel"
export OPENVAPT_CHANNELS_URL="file://$W/channels.txt"
export HOME="$W/home"
mkdir -p "$HOME"
unset DISPLAY WAYLAND_DISPLAY OPENVAPT_CHANNEL OPENVAPT_VERSION OPENVAPT_INSTALL_DIR 2>/dev/null || true
export OPENVAPT_TEST_ANY_OS=1

# 1. file:// is refused without the test switch.
if sh "$W/install.sh" --dir "$W/b0" >"$W/o" 2>&1; then fail "file:// accepted without OPENVAPT_ALLOW_FILE"; fi
if [ "$(uname -s)" = Linux ]; then
	grep -q OPENVAPT_ALLOW_FILE "$W/o" || { cat "$W/o"; fail "refused for another reason"; }
fi
pass "file:// refused without OPENVAPT_ALLOW_FILE=1"
export OPENVAPT_ALLOW_FILE=1

# 1b. A non-HTTPS channel list or release location is refused with a reason.
for var in OPENVAPT_CHANNELS_URL OPENVAPT_BASE_URL; do
	if env "$var=http://example.invalid/x" sh "$W/install.sh" --dir "$W/b0b" >"$W/o" 2>&1; then fail "$var over http accepted"; fi
	grep -q "$var must be an https:// URL" "$W/o" || { cat "$W/o"; fail "$var: no clear reason"; }
	[ ! -e "$W/b0b/openvapt" ] || fail "$var: something was installed"
done
pass "non-HTTPS OPENVAPT_CHANNELS_URL and OPENVAPT_BASE_URL are refused with a clear reason"

# 2. Channel fallback and Download Only.
sh "$W/install.sh" --dir "$W/b1" >"$W/o" 2>&1 || { cat "$W/o"; fail "default install"; }
grep -q "there is no Stable release yet" "$W/o" || fail "no pre-release warning"
grep -q "from the Alpha channel (v0.0.0-alpha.1)" "$W/o" || fail "warning does not name the channel"
grep -q "Installed (Download Only). Nothing has been scanned." "$W/o" || fail "no Download Only message"
for want in "scan --dry-run" "sudo .*openvapt scan" "openvapt-reports"; do grep -q "$want" "$W/o" || fail "next steps miss $want"; done
[ -x "$W/b1/openvapt" ] || fail "binary not installed"
[ ! -e "$HOME/openvapt-reports" ] || fail "Download Only created a reports folder"
pass "default picks the most stable channel with a release and warns; Download Only prints next steps"

printf 'beta v0.0.0-alpha.1 0 2026-10-14\nalpha v0.0.0-alpha.2 0 2026-10-14\n' >"$W/channels2.txt"
OPENVAPT_CHANNELS_URL="file://$W/channels2.txt" sh "$W/install.sh" --dir "$W/b1b" >"$W/o" 2>&1 || { cat "$W/o"; fail "beta fallback"; }
grep -q "from the Beta channel" "$W/o" || fail "beta should win over alpha"
pass "beta is preferred over alpha"

# 3. A forced channel without a release fails clearly.
if sh "$W/install.sh" --channel stable --dir "$W/b2" >"$W/o" 2>&1; then fail "--channel stable installed without a release"; fi
grep -q "no stable release is published (channels with a release: alpha v0.0.0-alpha.1)" "$W/o" || { cat "$W/o"; fail "unclear message"; }
pass "--channel stable without a release fails and lists the channels that have one"

# 4. Option errors.
for opt in --sudo --open "--out $W/x"; do
	# shellcheck disable=SC2086
	if sh "$W/install.sh" $opt --dir "$W/b3" >"$W/o" 2>&1; then fail "$opt accepted without --run"; fi
	grep -q "add --run" "$W/o" || fail "$opt: unclear message"
done
pass "--sudo, --open and --out need --run"

# 5. --dry-run previews and scans nothing.
sh "$W/install.sh" --dry-run --dir "$W/b4" >"$W/o" 2>&1 || { cat "$W/o"; fail "--dry-run"; }
grep -q "Nothing was scanned and no report was written" "$W/o" || fail "--dry-run message"
grep -q "Dry run: nothing will be read or executed" "$W/o" || fail "--dry-run did not run the preview"
[ ! -e "$HOME/openvapt-reports" ] || fail "--dry-run created a reports folder"
pass "--dry-run previews and writes nothing"

# 6. --run without a terminal is refused before anything is scanned.
if command -v setsid >/dev/null 2>&1; then NOTTY="setsid"; elif (: </dev/tty) 2>/dev/null; then NOTTY=""; else NOTTY="env"; fi
if [ -n "$NOTTY" ]; then
	if $NOTTY sh "$W/install.sh" --run --version v0.0.0-alpha.2 --dir "$W/b5" </dev/null >"$W/o" 2>&1; then fail "--run without a terminal succeeded"; fi
	grep -q "needs an interactive terminal" "$W/o" || { cat "$W/o"; fail "--run refusal message"; }
	[ ! -e "$HOME/openvapt-reports" ] || fail "--run without a terminal created a reports folder"
	pass "--run refuses without a terminal"
else
	echo "skip: --run without a terminal (this shell has a terminal and setsid is missing)"
fi

# in_pty INPUT COMMAND: run COMMAND in a new pseudo-terminal, typing INPUT.
in_pty() {
	if script -qec true /dev/null >/dev/null 2>&1; then
		{ sleep 2; printf '%s\n' "$1"; sleep 30; } | script -qec "$2" /dev/null
	else
		{ sleep 2; printf '%s\n' "$1"; sleep 30; } | script -q /dev/null sh -c "$2"
	fi
}
if ! command -v script >/dev/null 2>&1; then
	echo "skip: Download and Scan cases (script(1) is not installed)"
	exit 0
fi

# 7. Download and Scan: accepting writes all four reports in a dated folder.
in_pty "I ACCEPT" "sh $W/install.sh --run --version v0.0.0-alpha.2 --dir $W/b6 >$W/o 2>&1; echo \$? >$W/rc" >/dev/null 2>&1 || true
[ "$(cat "$W/rc")" = 0 ] || { cat "$W/o"; fail "--run exit $(cat "$W/rc")"; }
dated=$(find "$HOME/openvapt-reports" -mindepth 1 -maxdepth 1 -type d | head -n 1)
case "$(basename "$dated")" in [0-9][0-9][0-9][0-9][0-9][0-9][0-9][0-9]T[0-9][0-9][0-9][0-9][0-9][0-9]Z*) ;; *) fail "folder name $dated" ;; esac
for f in report.html report.json report.sarif report.md; do [ -s "$dated/$f" ] || fail "missing $f"; grep -q "  $dated/$f" "$W/o" || fail "$f path not printed"; done
[ -n "$(find "$dated" -maxdepth 0 -perm 700)" ] || fail "reports folder is not mode 0700"
for want in "type I ACCEPT" "Summary: Critical [0-9]" "Exit code 3: findings at or above High" "xdg-open $dated/report.html"; do
	grep -q "$want" "$W/o" || { cat "$W/o"; fail "--run output misses $want"; }
done
pass "Download and Scan in a terminal: acknowledgements, I ACCEPT, four reports in $(basename "$dated") (0700), summary, exit code and paths"
cp "$W/o" "${OPENVAPT_TEST_KEEP:-/dev/null}" 2>/dev/null || true
[ -z "${OPENVAPT_TEST_KEEP:-}" ] || ls -l "$dated" >>"$OPENVAPT_TEST_KEEP"

# 8. Cancelling writes nothing.
before=$(find "$HOME/openvapt-reports" -mindepth 1 -maxdepth 1 | wc -l)
in_pty "no" "sh $W/install.sh --run --version v0.0.0-alpha.2 --dir $W/b7 >$W/o 2>&1; echo \$? >$W/rc" >/dev/null 2>&1 || true
[ "$(cat "$W/rc")" != 0 ] || fail "cancelled scan returned 0"
grep -q "nothing was scanned" "$W/o" || { cat "$W/o"; fail "cancel message"; }
after=$(find "$HOME/openvapt-reports" -mindepth 1 -maxdepth 1 -type d -exec sh -c 'ls -A "$1" | grep -q .' _ {} \; -print | wc -l)
[ "$after" -le "$before" ] || fail "a cancelled scan wrote reports"
pass "typing anything but I ACCEPT cancels and writes no report"

# 9. --out chooses the folder; an existing folder is refused.
in_pty "I ACCEPT" "sh $W/install.sh --run --out $W/mine --version v0.0.0-alpha.2 --dir $W/b8 >$W/o 2>&1; echo \$? >$W/rc" >/dev/null 2>&1 || true
[ "$(cat "$W/rc")" = 0 ] || { cat "$W/o"; fail "--out exit"; }
for f in report.html report.json report.sarif report.md; do [ -s "$W/mine/$f" ] || fail "--out missing $f"; done
if sh "$W/install.sh" --run --out "$W/mine" --version v0.0.0-alpha.2 --dir "$W/b9" >"$W/o" 2>&1 </dev/null; then fail "existing --out accepted"; fi
pass "--out writes the four reports into the chosen folder"

# 10. A tampered binary is refused and nothing is installed.
printf 'x' >>"$W/rel/download/v0.0.0-alpha.1/$B"
if sh "$W/install.sh" --version v0.0.0-alpha.1 --dir "$W/b10" >"$W/o" 2>&1; then fail "tampered binary installed"; fi
grep -q "checksum mismatch" "$W/o" || fail "no checksum message"
[ ! -e "$W/b10/openvapt" ] || fail "tampered binary left behind"
pass "a bad checksum is refused and nothing is installed"

echo "installer end-to-end test passed"
