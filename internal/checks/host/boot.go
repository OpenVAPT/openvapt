package host

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// Boot and integrity: boot loader password, Secure Boot state, kernel module
// restrictions, file integrity monitoring, prelink and core dumps. Every
// check reads files only; no command is run.
//
// Sources: GNU GRUB manual, UEFI Specification, Linux kernel documentation,
// NIST SP 800-123, NIST SP 800-53 CM-6, CM-7, SI-7 and AC-6, CIS Controls
// v8 safeguards 4.1 and 4.8 by id.

var (
	refGrubSec   = check.Ref{Title: "GNU GRUB Manual, Security", URL: "https://www.gnu.org/software/grub/manual/grub/html_node/Security.html"}
	refUEFI      = check.Ref{Title: "UEFI Specification, Secure Boot and Driver Signing", URL: "https://uefi.org/specs/UEFI/2.10/32_Secure_Boot_and_Driver_Signing.html"}
	refModprobeD = check.Ref{Title: "modprobe.d(5), Linux man-pages", URL: "https://man7.org/linux/man-pages/man5/modprobe.d.5.html"}
	refModSign   = check.Ref{Title: "Linux kernel documentation, Kernel module signing facility", URL: "https://docs.kernel.org/admin-guide/module-signing.html"}
	refAIDE      = check.Ref{Title: "AIDE, Advanced Intrusion Detection Environment", URL: "https://aide.github.io/"}
	refLimits    = check.Ref{Title: "limits.conf(5), Linux-PAM", URL: "https://man7.org/linux/man-pages/man5/limits.conf.5.html"}
	refCoredump  = check.Ref{Title: "coredump.conf(5), systemd", URL: "https://www.freedesktop.org/software/systemd/man/latest/coredump.conf.html"}
)

// readSome reads path and reports (text, exists, readable). A file that is
// absent is a normal observation; one that exists but cannot be read fully
// must make a check incomplete rather than pass.
func readSome(ctx context.Context, s sys.System, path string) (string, bool, bool) {
	r, err := s.ReadFile(ctx, path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", false, true
		}
		return "", true, false
	}
	return string(r.Data), true, r.Complete
}

// fsModules are filesystem drivers a server almost never needs. Each one
// has carried kernel bugs reachable by mounting a crafted image.
var fsModules = []string{"cramfs", "freevxfs", "jffs2", "hfs", "hfsplus", "udf", "squashfs"}

// modprobeState reports, for each module, whether /etc/modprobe.d disables
// it (install <mod> /bin/false or /bin/true, or blacklist <mod>). Both
// forms count; the strictest hardening uses both. unreadable is true when
// a modprobe.d file exists but could not be read.
func modprobeState(ctx context.Context, s sys.System, mods []string) (map[string][]string, bool) {
	state := map[string][]string{}
	files, _ := s.Glob("/etc/modprobe.d/*.conf")
	more, _ := s.Glob("/usr/lib/modprobe.d/*.conf")
	files = append(files, more...)
	sort.Strings(files)
	unreadable := false
	for _, f := range files {
		text, _, ok := readSome(ctx, s, f)
		if !ok {
			unreadable = true
			continue
		}
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(strings.TrimSpace(line))
			if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			name := strings.ReplaceAll(fields[1], "-", "_")
			for _, m := range mods {
				if name != strings.ReplaceAll(m, "-", "_") {
					continue
				}
				switch {
				case fields[0] == "install" && len(fields) >= 3 && (fields[2] == "/bin/false" || fields[2] == "/bin/true" || fields[2] == "/usr/bin/false" || fields[2] == "/usr/bin/true"):
					state[m] = append(state[m], "install "+fields[1]+" "+fields[2]+" ("+f+")")
				case fields[0] == "blacklist":
					state[m] = append(state[m], "blacklist "+fields[1]+" ("+f+")")
				}
			}
		}
	}
	return state, unreadable
}

func init() {
	check.Register(&check.Check{
		ID: "HOST-BOOT-001", Title: "Boot Loader Has No Password", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatAccess, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks that GRUB is configured with a superuser and a hashed password so the boot entries cannot be edited at the console.",
		Rationale: "Without a boot loader password anyone at the console or virtual console can edit the kernel command line (for example add init=/bin/bash) and get a root shell without any credentials, bypassing every control on the running system.",
		Detection: "Reads /boot/grub/grub.cfg, /boot/grub2/grub.cfg, /boot/grub2/user.cfg, /boot/efi/EFI/*/grub.cfg, /boot/efi/EFI/*/user.cfg and /etc/grub.d/* and looks for  set superusers=  together with  password_pbkdf2  (or password). Only the presence of these directives is reported; hashes are never shown. Skipped when no GRUB configuration exists; incomplete when a file exists but cannot be read.",
		Fix:       "Run  grub-mkpasswd-pbkdf2  (grub2-setpassword on RHEL family), add  set superusers=\"admin\"  and  password_pbkdf2 admin <hash>  to /etc/grub.d/40_custom (RHEL family writes /boot/grub2/user.cfg), then regenerate with  update-grub  or  grub2-mkconfig -o /boot/grub2/grub.cfg. Add  --unrestricted  to the normal menu entry so unattended reboots still work.",
		Verify:    "grep -E 'set superusers|password_pbkdf2' /boot/grub/grub.cfg /boot/grub2/grub.cfg /boot/grub2/user.cfg /etc/grub.d/* 2>/dev/null | sed 's/grub.pbkdf2.*/<hash>/'",
		Refs:      []check.Ref{refGrubSec, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-306"}, NIST: []string{"AC-3", "AC-6", "CM-6"}, CISTopic: "Boot loader password (CIS Controls v8 4.1)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			paths := []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg", "/boot/grub2/user.cfg", "/boot/grub/user.cfg"}
			for _, pat := range []string{"/boot/efi/EFI/*/grub.cfg", "/boot/efi/EFI/*/user.cfg", "/etc/grub.d/*"} {
				more, _ := s.Glob(pat)
				sort.Strings(more)
				paths = append(paths, more...)
			}
			var super, pass []string
			seen, unreadable := 0, 0
			for _, p := range paths {
				text, exists, ok := readSome(ctx, s, p)
				if !exists {
					continue
				}
				seen++
				if !ok {
					unreadable++
					continue
				}
				if grubSuperusers.MatchString(text) {
					super = append(super, p)
				}
				if grubPassword.MatchString(text) {
					pass = append(pass, p)
				}
			}
			switch {
			case seen == 0:
				return []check.Result{check.SkipR("/boot/grub", "No GRUB configuration found")}
			case len(super) > 0 && len(pass) > 0:
				return []check.Result{check.PassR("/boot/grub", "GRUB has a superuser and a hashed password", "superusers in "+strings.Join(super, ", "), "password directive in "+strings.Join(pass, ", "))}
			case unreadable > 0:
				return []check.Result{check.IncompleteR("/boot/grub", fmt.Sprintf("%d GRUB file(s) could not be read; no password directive found in the readable ones", unreadable))}
			case len(super) > 0:
				return []check.Result{check.FailR("/boot/grub", "GRUB names a superuser but sets no password", "superusers in "+strings.Join(super, ", "))}
			default:
				return []check.Result{check.FailR("/boot/grub", fmt.Sprintf("No superuser or password directive in %d GRUB file(s)", seen))}
			}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-BOOT-002", Title: "UEFI Secure Boot Disabled", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatConfig, Effort: check.EffortHigh,
		CVSS:      "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks the firmware's SecureBoot variable to see whether the boot chain is verified.",
		Rationale: "Secure Boot makes the firmware refuse unsigned boot loaders and kernels, which blocks boot kits and unsigned kernels planted by an attacker with disk or console access. Without it, anything written to the boot partition runs at the next reboot.",
		Detection: "Reads /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c (the four-byte attribute header followed by one data byte; 1 means enabled). Machines without /sys/firmware/efi boot in legacy BIOS mode and are skipped, as are UEFI machines that expose no SecureBoot variable; an unreadable variable is incomplete. No command such as mokutil is run.",
		Fix:       "Enable Secure Boot in the firmware set-up and boot a signed shim and kernel (every mainstream distribution ships them). Custom kernels and out-of-tree modules then need signing with a Machine Owner Key. Where the platform cannot do Secure Boot, record the exception.",
		Verify:    "mokutil --sb-state  or  od -An -t u1 /sys/firmware/efi/efivars/SecureBoot-*  (the fifth byte is 1 when enabled).",
		Refs:      []check.Ref{refUEFI, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-1326"}, NIST: []string{"SI-7", "CM-6"}, CISTopic: "Boot integrity (CIS Controls v8 4.1)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			vars, _ := s.Glob("/sys/firmware/efi/efivars/SecureBoot-*")
			if len(vars) == 0 {
				if _, err := s.Stat("/sys/firmware/efi"); errors.Is(err, fs.ErrNotExist) {
					return []check.Result{check.SkipR("/sys/firmware/efi", "Legacy BIOS boot; Secure Boot does not apply")}
				}
				return []check.Result{check.SkipR("/sys/firmware/efi/efivars", "UEFI firmware exposes no SecureBoot variable")}
			}
			sort.Strings(vars)
			r, err := s.ReadFile(ctx, vars[0])
			if err != nil || !r.Complete || len(r.Data) < 5 {
				return []check.Result{check.IncompleteR(vars[0], "SecureBoot variable could not be read")}
			}
			if r.Data[4] == 1 {
				return []check.Result{check.PassR(vars[0], "Secure Boot is enabled", "SecureBoot = 1")}
			}
			return []check.Result{check.FailR(vars[0], "Secure Boot is disabled", fmt.Sprintf("SecureBoot = %d", r.Data[4]))}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-BOOT-003", Title: "Uncommon Filesystem Modules Not Disabled", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Checks that the cramfs, freevxfs, jffs2, hfs, hfsplus, udf and squashfs kernel modules are disabled in modprobe.d.",
		Rationale: "Each filesystem driver is kernel code that parses untrusted data. A local user who can mount removable media or a loop device gets the kernel to parse a crafted image with one of these rarely maintained drivers, and several have had memory-corruption bugs. Removing drivers nobody uses removes that attack surface.",
		Detection: "Reads /etc/modprobe.d/*.conf and /usr/lib/modprobe.d/*.conf and, for each module, accepts  install <module> /bin/false  (or /bin/true) or  blacklist <module>. squashfs is left out when /snap exists because snaps need it. Modules with neither line fail; an unreadable modprobe.d file makes the check incomplete.",
		Fix:       "Create /etc/modprobe.d/openvapt-filesystems.conf with, for each module:  install <module> /bin/false  and  blacklist <module>  then unload any loaded one with  modprobe -r <module>.",
		Verify:    "for m in cramfs freevxfs jffs2 hfs hfsplus udf squashfs; do modprobe -n -v $m; lsmod | grep -w $m; done",
		Refs:      []check.Ref{refModprobeD, refKSPP},
		Standards: check.Standards{CWE: []string{"CWE-1188"}, NIST: []string{"CM-7", "CM-6"}, CISTopic: "Disable unused filesystem kernel modules (CIS Controls v8 4.8)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			mods := fsModules
			if _, err := s.Stat("/snap"); err == nil {
				mods = mods[:len(mods)-1]
			}
			state, unreadable := modprobeState(ctx, s, mods)
			var missing, ev []string
			for _, m := range mods {
				if len(state[m]) == 0 {
					missing = append(missing, m)
				} else {
					ev = append(ev, state[m]...)
				}
			}
			if len(missing) > 0 {
				if unreadable {
					return []check.Result{check.IncompleteR("/etc/modprobe.d", "Some modprobe.d files could not be read; not disabled in the readable ones: "+strings.Join(missing, ", "))}
				}
				return []check.Result{check.FailR("/etc/modprobe.d", "Filesystem modules not disabled: "+strings.Join(missing, ", "), ev...)}
			}
			return []check.Result{check.PassR("/etc/modprobe.d", fmt.Sprintf("All %d uncommon filesystem modules are disabled", len(mods)), ev...)}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-BOOT-004", Title: "USB Storage Driver Not Disabled", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
		Summary:   "Checks that the usb-storage kernel module is disabled in modprobe.d on servers that do not need removable media.",
		Rationale: "A USB stick plugged into a server is the simplest way to copy data out or bring malware in without touching the network. Disabling the driver makes the device invisible to the kernel.",
		Detection: "Reads /etc/modprobe.d/*.conf and /usr/lib/modprobe.d/*.conf for  install usb-storage /bin/false  (or /bin/true) or  blacklist usb-storage. Neither present fails; an unreadable file makes the check incomplete.",
		Fix:       "Create /etc/modprobe.d/openvapt-usb.conf containing  install usb-storage /bin/false  and  blacklist usb-storage  then  modprobe -r usb-storage. Servers that need USB backups should record the exception instead.",
		Verify:    "modprobe -n -v usb-storage  should print install /bin/false; lsmod | grep usb_storage  should print nothing.",
		Refs:      []check.Ref{refModprobeD, {Title: "MITRE ATT&CK T1091, Replication Through Removable Media", URL: "https://attack.mitre.org/techniques/T1091/"}},
		Standards: check.Standards{CWE: []string{"CWE-1188"}, NIST: []string{"MP-7", "CM-7"}, CISTopic: "Disable USB storage (CIS Controls v8 4.8)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			state, unreadable := modprobeState(ctx, s, []string{"usb-storage"})
			if len(state["usb-storage"]) > 0 {
				return []check.Result{check.PassR("/etc/modprobe.d", "usb-storage is disabled", state["usb-storage"]...)}
			}
			if unreadable {
				return []check.Result{check.IncompleteR("/etc/modprobe.d", "Some modprobe.d files could not be read; usb-storage is not disabled in the readable ones")}
			}
			return []check.Result{check.FailR("/etc/modprobe.d", "usb-storage is not disabled in modprobe.d")}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-BOOT-005", Title: "Kernel Module Loading Unrestricted", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:L/I:L/A:L",
		Summary:   "Checks that the running kernel refuses unsigned modules or has module loading switched off entirely.",
		Rationale: "A root-level attacker who can load any module owns the kernel: rootkits hide processes and files from every tool on the box. Signature enforcement or kernel.modules_disabled = 1 after boot makes that persistence step fail.",
		Detection: "Reads /proc/sys/kernel/modules_disabled (1 passes), otherwise /sys/module/module/parameters/sig_enforce (Y passes) and /sys/kernel/security/lockdown ([integrity] or [confidentiality] passes). Kernels built without loadable module support are skipped; a value that exists but cannot be read is incomplete.",
		Fix:       "Boot with  module.sig_enforce=1  (or  lockdown=integrity) on the kernel command line and sign any out-of-tree modules, or set  kernel.modules_disabled = 1  from a late boot service once every needed module is loaded (it cannot be turned back on without a reboot).",
		Verify:    "sysctl kernel.modules_disabled; cat /sys/module/module/parameters/sig_enforce /sys/kernel/security/lockdown",
		Refs:      []check.Ref{refModSign, refKSPP},
		Standards: check.Standards{CWE: []string{"CWE-693"}, NIST: []string{"SI-7", "CM-7"}, CISTopic: "Restrict kernel module loading (CIS Controls v8 4.8)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			v, err := collect.Sysctl(s, "kernel.modules_disabled")
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return []check.Result{check.SkipR("kernel.modules_disabled", "Kernel has no loadable module support")}
				}
				return []check.Result{check.IncompleteR("kernel.modules_disabled", "Parameter could not be read")}
			}
			if v == "1" {
				return []check.Result{check.PassR("kernel.modules_disabled", "Module loading is disabled for this boot", "kernel.modules_disabled = 1")}
			}
			var ev []string
			for _, p := range []string{"/sys/module/module/parameters/sig_enforce", "/sys/kernel/security/lockdown"} {
				text, exists, ok := readSome(ctx, s, p)
				if !exists {
					continue
				}
				if !ok {
					return []check.Result{check.IncompleteR(p, "Value could not be read")}
				}
				text = strings.TrimSpace(text)
				ev = append(ev, p+" = "+text)
				if (strings.HasSuffix(p, "sig_enforce") && text == "Y") || strings.Contains(text, "[integrity]") || strings.Contains(text, "[confidentiality]") {
					return []check.Result{check.PassR("kernel modules", "Unsigned modules are refused", ev...)}
				}
			}
			return []check.Result{check.FailR("kernel.modules_disabled", "Any module can be loaded: modules_disabled = "+v+" and no signature enforcement or lockdown", ev...)}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-BOOT-006", Title: "No File Integrity Monitoring", Domain: check.DomainHost,
		Severity: check.Medium, Category: check.CatLogging, Effort: check.EffortMedium,
		CVSS:      "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:N/I:H/A:N",
		Summary:   "Checks that a file integrity tool (AIDE, Tripwire, Samhain or equivalent) is installed and scheduled to run.",
		Rationale: "After a compromise the first question is which files changed. Without a baseline and a scheduled comparison, a replaced binary, an added SUID file or an edited PAM stack stays invisible for months.",
		Detection: "Looks for the tools' programs and configuration (/usr/bin/aide, /usr/sbin/aide, /etc/aide/aide.conf, /etc/aide.conf, /usr/sbin/tripwire, /etc/tripwire, /usr/sbin/samhain, /etc/samhainrc, /usr/sbin/osqueryd and /opt/ossec/bin/ossec-syscheckd) and then for a schedule: a file in /etc/cron.d, /etc/cron.daily or /etc/cron.weekly, a systemd timer under /etc/systemd/system or /usr/lib/systemd/system, or a line in /etc/crontab that names the tool. Tool present with no schedule still fails. Stat and glob only; configuration contents are not read except /etc/crontab.",
		Fix:       "Install AIDE (apt install aide / dnf install aide), initialise the database with  aideinit  or  aide --init, move the new database into place, and enable the daily check (dailyaidecheck.timer on Debian family, or a cron.daily entry) that mails or logs the differences.",
		Verify:    "aide --check  (or your tool's check command) runs and reports; systemctl list-timers | grep -i aide  or  ls /etc/cron.daily | grep -i aide",
		Refs:      []check.Ref{refAIDE, refNIST80053, refNIST800123},
		Standards: check.Standards{CWE: []string{"CWE-778"}, NIST: []string{"SI-7", "CM-3"}, CISTopic: "File integrity checking (CIS Controls v8 4.1)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			tools := []struct {
				name  string
				paths []string
			}{
				{"aide", []string{"/usr/bin/aide", "/usr/sbin/aide", "/etc/aide/aide.conf", "/etc/aide.conf"}},
				{"tripwire", []string{"/usr/sbin/tripwire", "/etc/tripwire"}},
				{"samhain", []string{"/usr/sbin/samhain", "/etc/samhainrc"}},
				{"osquery", []string{"/usr/sbin/osqueryd", "/usr/bin/osqueryd"}},
				{"ossec", []string{"/opt/ossec/bin/ossec-syscheckd", "/var/ossec/bin/ossec-syscheckd", "/var/ossec/bin/wazuh-syscheckd"}},
			}
			var installed []string
			for _, t := range tools {
				for _, p := range t.paths {
					if _, err := s.Stat(p); err == nil {
						installed = append(installed, t.name)
						break
					}
				}
			}
			if len(installed) == 0 {
				return []check.Result{check.FailR("integrity", "No file integrity tool found (AIDE, Tripwire, Samhain, osquery or OSSEC)")}
			}
			var sched []string
			for _, name := range installed {
				if name == "osquery" || name == "ossec" {
					sched = append(sched, name+" runs as a daemon")
					continue
				}
				for _, pat := range []string{"/etc/cron.d/*", "/etc/cron.daily/*", "/etc/cron.weekly/*", "/etc/systemd/system/*.timer", "/etc/systemd/system/timers.target.wants/*.timer", "/usr/lib/systemd/system/*.timer", "/lib/systemd/system/*.timer"} {
					paths, _ := s.Glob(pat)
					sort.Strings(paths)
					for _, p := range paths {
						if strings.Contains(strings.ToLower(p), name) {
							sched = append(sched, p)
						}
					}
				}
				if text, _, ok := readSome(ctx, s, "/etc/crontab"); ok && strings.Contains(text, name) {
					sched = append(sched, "/etc/crontab names "+name)
				}
			}
			if len(sched) == 0 {
				return []check.Result{check.FailR("integrity", strings.Join(installed, ", ")+" installed but no scheduled check was found")}
			}
			return []check.Result{check.PassR("integrity", strings.Join(installed, ", ")+" installed and scheduled", sched...)}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-BOOT-007", Title: "Prelink Installed", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatConfig, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:H/UI:N/S:U/C:N/I:L/A:N",
		Summary:   "Checks that the prelink tool is absent, or disabled where the package is still installed.",
		Rationale: "Prelink rewrites binaries and libraries in place, which changes their hashes and defeats integrity monitoring and package verification, and it weakens address randomisation by fixing load addresses. Modern systems gain nothing from it.",
		Detection: "Stats /usr/sbin/prelink, /usr/bin/prelink and /etc/prelink.conf. If any exists, reads /etc/sysconfig/prelink and /etc/default/prelink for  PRELINKING=no, which passes with a note. Absent files pass; a stat error other than not-found is incomplete.",
		Fix:       "Undo and remove it:  prelink -ua && apt purge prelink  (or  dnf remove prelink). Then re-initialise the integrity database (aide --init).",
		Verify:    "command -v prelink  should print nothing.",
		Refs:      []check.Ref{{Title: "prelink(8), Linux man-pages", URL: "https://man7.org/linux/man-pages/man8/prelink.8.html"}, refNIST80053},
		Standards: check.Standards{CWE: []string{"CWE-693"}, NIST: []string{"SI-7", "CM-7"}, CISTopic: "Prelink not installed (CIS Controls v8 4.8)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var found []string
			for _, p := range []string{"/usr/sbin/prelink", "/usr/bin/prelink", "/etc/prelink.conf"} {
				_, err := s.Stat(p)
				switch {
				case err == nil:
					found = append(found, p)
				case !errors.Is(err, fs.ErrNotExist):
					return []check.Result{check.IncompleteR(p, "Could not stat "+p)}
				}
			}
			if len(found) == 0 {
				return []check.Result{check.PassR("prelink", "Prelink is not installed")}
			}
			for _, cfg := range []string{"/etc/sysconfig/prelink", "/etc/default/prelink"} {
				text, exists, ok := readSome(ctx, s, cfg)
				if exists && !ok {
					return []check.Result{check.IncompleteR(cfg, "Prelink configuration could not be read")}
				}
				if prelinkOff.MatchString(text) {
					return []check.Result{check.PassR("prelink", "Prelink is installed but disabled (PRELINKING=no); removing the package is cleaner", found...)}
				}
			}
			return []check.Result{check.FailR("prelink", "Prelink is installed", found...)}
		},
	})

	check.Register(&check.Check{
		ID: "HOST-BOOT-008", Title: "Core Dumps Not Restricted", Domain: check.DomainHost,
		Severity: check.Low, Category: check.CatExposure, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N",
		Summary:   "Checks that process core dumps are turned off through PAM limits, and through systemd-coredump where the kernel hands dumps to it.",
		Rationale: "A core dump is a copy of a program's memory, including passwords, keys and session tokens it held. On a server nobody debugs, dumps are only a leak waiting in /var/lib/systemd/coredump or the working directory. HOST-KRN-004 covers setuid programs; this check covers every process.",
		Detection: "Reads /etc/security/limits.conf and /etc/security/limits.d/*.conf for a  * hard core 0  line, and /proc/sys/kernel/core_pattern. When the pattern pipes dumps to systemd-coredump, /etc/systemd/coredump.conf and /etc/systemd/coredump.conf.d/*.conf must set  Storage=none  (ProcessSizeMax=0 also counts). Either the limits line or the systemd setting passes. Missing files are observed as missing; a file that exists but cannot be read makes the check incomplete.",
		Fix:       "Add  * hard core 0  to /etc/security/limits.conf (or a file in limits.d), set  Storage=none  and  ProcessSizeMax=0  in the [Coredump] section of /etc/systemd/coredump.conf, and keep  fs.suid_dumpable = 0.",
		Verify:    "grep -E '^\\*\\s+hard\\s+core\\s+0' /etc/security/limits.conf /etc/security/limits.d/*; grep -E '^(Storage|ProcessSizeMax)' /etc/systemd/coredump.conf; cat /proc/sys/kernel/core_pattern",
		Refs:      []check.Ref{refLimits, refCoredump, refKernelDocs},
		Standards: check.Standards{CWE: []string{"CWE-528"}, NIST: []string{"SI-11", "CM-6", "AC-6"}, CISTopic: "Restrict core dumps (CIS Controls v8 4.1)"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var ev []string
			partial := false
			files := []string{"/etc/security/limits.conf"}
			more, _ := s.Glob("/etc/security/limits.d/*.conf")
			sort.Strings(more)
			files = append(files, more...)
			limited := false
			for _, p := range files {
				text, exists, ok := readSome(ctx, s, p)
				if !exists {
					continue
				}
				if !ok {
					partial = true
					continue
				}
				if hardCore0.MatchString(text) {
					limited = true
					ev = append(ev, p+": * hard core 0")
				}
			}
			pattern, _, _ := readSome(ctx, s, "/proc/sys/kernel/core_pattern")
			pattern = strings.TrimSpace(pattern)
			if pattern != "" {
				ev = append(ev, "kernel.core_pattern = "+pattern)
			}
			systemdOff := false
			if strings.Contains(pattern, "systemd-coredump") {
				cfgs := []string{"/etc/systemd/coredump.conf"}
				more, _ := s.Glob("/etc/systemd/coredump.conf.d/*.conf")
				sort.Strings(more)
				cfgs = append(cfgs, more...)
				for _, p := range cfgs {
					text, exists, ok := readSome(ctx, s, p)
					if !exists {
						continue
					}
					if !ok {
						partial = true
						continue
					}
					if storageNone.MatchString(text) {
						systemdOff = true
						ev = append(ev, p+": Storage=none or ProcessSizeMax=0")
					}
				}
			}
			switch {
			case limited || systemdOff:
				return []check.Result{check.PassR("core dumps", "Core dumps are restricted", ev...)}
			case partial:
				return []check.Result{check.IncompleteR("core dumps", "A limits or coredump configuration file could not be read", ev...)}
			default:
				return []check.Result{check.FailR("core dumps", "No hard core 0 limit and no systemd-coredump Storage=none", ev...)}
			}
		},
	})
}

var (
	grubSuperusers = regexp.MustCompile(`(?m)^\s*set\s+superusers\s*=`)
	grubPassword   = regexp.MustCompile(`(?m)^\s*password(_pbkdf2)?\s+\S+\s+\S+`)
	prelinkOff     = regexp.MustCompile(`(?mi)^\s*PRELINKING\s*=\s*"?no"?\s*$`)
	hardCore0      = regexp.MustCompile(`(?m)^\s*\*\s+(hard|-)\s+core\s+0\s*$`)
	storageNone    = regexp.MustCompile(`(?mi)^\s*(Storage\s*=\s*none|ProcessSizeMax\s*=\s*0)\s*$`)
)
