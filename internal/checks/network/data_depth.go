package network

import (
	"context"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

// NET-DB-014 to NET-DB-023: database hardening depth for MySQL or MariaDB,
// PostgreSQL and Redis, read from option files only. Nothing connects to a
// database or runs a client. NET-DB-002 to NET-DB-005 already cover network
// binding, trust authentication, local_infile and skip-grant-tables, so
// those signals are not repeated here.

// depthRule is a configuration-file check with explicit metadata. Unlike
// configRule it carries its own standards and effort, and it distinguishes
// "service absent" (Skip) from "service installed but unreadable"
// (Incomplete) by probing marker paths.
type depthRule struct {
	id, title                                string
	sev                                      check.Severity
	cat                                      check.Category
	cvss, summary, rationale, detection, fix string
	verify                                   string
	patterns                                 []string
	markers                                  []string // folders or binaries that mean the service is installed
	refs                                     []check.Ref
	std                                      check.Standards
	evaluate                                 func(fs []collect.ConfigFile) (bad bool, ev []string)
	// evaluateSys, when set, replaces evaluate for rules that must also read
	// the system (for example the crypto library floor). A non-empty pass
	// string replaces passMsg so the Pass can say why.
	evaluateSys func(ctx context.Context, s sys.System, fs []collect.ConfigFile) (bad bool, ev []string, pass string)
	passMsg     string
}

func installed(s sys.System, markers []string) bool {
	for _, m := range markers {
		if _, err := s.Stat(m); err == nil {
			return true
		}
	}
	return false
}

func registerDepth(r depthRule) {
	check.Register(&check.Check{
		ID: r.id, Title: r.title, Domain: check.DomainNetwork, Severity: r.sev, Category: r.cat, Effort: check.EffortLow, CVSS: r.cvss,
		Summary: r.summary, Rationale: r.rationale, Detection: r.detection, Fix: r.fix, Verify: r.verify, Refs: r.refs, Standards: r.std,
		Run: func(ctx context.Context, s sys.System) []check.Result {
			fs := collect.ReadConfigs(ctx, s, r.patterns...)
			target := strings.Join(r.patterns, ", ")
			if len(fs) == 0 {
				if installed(s, r.markers) {
					return []check.Result{check.IncompleteR(target, "The service appears installed but its configuration could not be read")}
				}
				return []check.Result{check.SkipR(target, "Service configuration was not found")}
			}
			var bad bool
			var ev []string
			var pass string
			if r.evaluateSys != nil {
				bad, ev, pass = r.evaluateSys(ctx, s, fs)
			} else {
				bad, ev = r.evaluate(fs)
			}
			if bad {
				return []check.Result{check.FailR(fs[0].Path, r.summary, ev...)}
			}
			if anyIncomplete(fs) {
				return []check.Result{check.IncompleteR(fs[0].Path, "Configuration input was truncated; the setting could not be confirmed")}
			}
			msg := r.passMsg
			if pass != "" {
				msg = pass
			}
			if msg == "" {
				msg = "The hardening setting is present"
			}
			return []check.Result{check.PassR(fs[0].Path, msg, ev...)}
		},
	})
}

var (
	mysqlFiles   = []string{"/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/*.cnf", "/etc/mysql/mariadb.conf.d/*.cnf", "/etc/mysql/conf.d/*.cnf", "/etc/my.cnf", "/etc/my.cnf.d/*.cnf"}
	mysqlMarkers = []string{"/etc/mysql", "/etc/my.cnf.d", "/usr/sbin/mysqld", "/usr/sbin/mariadbd"}
	pgConf       = []string{"/etc/postgresql/*/main/postgresql.conf", "/var/lib/pgsql/data/postgresql.conf", "/var/lib/pgsql/*/data/postgresql.conf"}
	pgHBA        = []string{"/etc/postgresql/*/main/pg_hba.conf", "/var/lib/pgsql/data/pg_hba.conf", "/var/lib/pgsql/*/data/pg_hba.conf"}
	pgMarkers    = []string{"/etc/postgresql", "/var/lib/pgsql", "/usr/lib/postgresql"}
	redisFiles   = []string{"/etc/redis/redis.conf", "/etc/redis.conf"}
	redisMarkers = []string{"/etc/redis", "/usr/bin/redis-server"}

	refMySQLSec   = check.Ref{Title: "MySQL 8.4 Reference Manual, Security Guidelines", URL: "https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html"}
	refMySQLOpts  = check.Ref{Title: "MySQL 8.4 Reference Manual, Server System Variables", URL: "https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html"}
	refPGAuth     = check.Ref{Title: "PostgreSQL, Authentication Methods", URL: "https://www.postgresql.org/docs/current/auth-methods.html"}
	refPGConn     = check.Ref{Title: "PostgreSQL, Connections and Authentication", URL: "https://www.postgresql.org/docs/current/runtime-config-connection.html"}
	refPGSSL      = check.Ref{Title: "PostgreSQL, Secure TCP/IP Connections with SSL", URL: "https://www.postgresql.org/docs/current/ssl-tcp.html"}
	refPGLog      = check.Ref{Title: "PostgreSQL, Error Reporting and Logging", URL: "https://www.postgresql.org/docs/current/runtime-config-logging.html"}
	refRedisSec   = check.Ref{Title: "Redis Security", URL: "https://redis.io/docs/latest/operate/oss_and_stack/management/security/"}
	refRedisACL   = check.Ref{Title: "Redis ACL", URL: "https://redis.io/docs/latest/operate/oss_and_stack/management/security/acl/"}
	refNISTSC8    = check.Ref{Title: "NIST SP 800-53 Rev. 5, SC-8 Transmission Confidentiality and Integrity", URL: "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"}
	refNISTDigest = check.Ref{Title: "NIST SP 800-63B, Digital Identity Guidelines: Authentication", URL: "https://pages.nist.gov/800-63-3/sp800-63b.html"}
)

// mysqlValue returns every value of key from the [mysqld] or [mariadb]
// sections, or unsectioned, accepting both dash and underscore spellings.
func mysqlValues(fs []collect.ConfigFile, key string) []string {
	// Only server sections count: ParseKV also records every key without
	// its section, which would let a [client] setting satisfy a [mysqld]
	// requirement.
	var keys []string
	for _, k := range []string{key, strings.ReplaceAll(key, "_", "-"), strings.ReplaceAll(key, "-", "_")} {
		keys = append(keys, "mysqld."+k, "mariadb."+k, "server."+k)
	}
	return values(fs, keys...)
}

func mysqlSet(fs []collect.ConfigFile, key string) bool { return len(mysqlValues(fs, key)) > 0 }

func anyMySQL(fs []collect.ConfigFile, key string, want func(string) bool) bool {
	for _, v := range mysqlValues(fs, key) {
		if want(v) {
			return true
		}
	}
	return false
}

func mysqlEvidence(fs []collect.ConfigFile, keys ...string) []string {
	var all []string
	for _, k := range keys {
		for _, kk := range []string{k, strings.ReplaceAll(k, "_", "-")} {
			all = append(all, "mysqld."+kk, "mariadb."+kk, "server."+kk)
		}
	}
	return evidence(fs, all...)
}

// pgValue returns the first effective value of a postgresql.conf setting,
// stripped of quotes. postgresql.conf lets later lines override earlier
// ones, so the last value wins.
func pgValue(fs []collect.ConfigFile, key string) (string, bool) {
	v := values(fs, key)
	if len(v) == 0 {
		return "", false
	}
	return strings.Trim(strings.TrimSpace(v[len(v)-1]), `'"`), true
}

var isOn = func(v string) bool { v = strings.ToLower(v); return v == "on" || v == "1" || v == "true" || v == "yes" }
var isOff = func(v string) bool {
	v = strings.ToLower(v)
	return v == "off" || v == "0" || v == "false" || v == "no"
}

func init() {
	dbStd := func(cwe []string, nist ...string) check.Standards {
		return check.Standards{CWE: cwe, OWASP: []string{"A05:2021"}, ASVS: []string{"14.1.3"}, NIST: nist, CISTopic: "Database server hardening"}
	}

	// MySQL / MariaDB
	registerDepth(depthRule{
		id: "NET-DB-014", title: "MySQL Symbolic Links Allowed for Tables", sev: check.Medium, cat: check.CatData,
		cvss:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L",
		summary:   "MySQL or MariaDB does not disable symbolic links for table files (skip-symbolic-links or symbolic-links=0).",
		rationale: "With symlinks allowed, a user who can create tables can point table files at paths outside the data directory and read or overwrite them with the server's privileges. The MySQL manual recommends disabling the feature unless it is needed.",
		detection: "Parses the MySQL and MariaDB option files for skip-symbolic-links, symbolic-links or skip_symbolic_links under [mysqld]. Fails when none disables the feature.",
		fix:       "Add  symbolic-links=0  (or  skip-symbolic-links ) under [mysqld] and restart the service in a maintenance window.",
		verify:    "SHOW VARIABLES LIKE 'have_symlink';  from an administrator session should print DISABLED.",
		patterns:  mysqlFiles, markers: mysqlMarkers,
		refs: []check.Ref{{Title: "MySQL 8.4 Reference Manual, Using Symbolic Links", URL: "https://dev.mysql.com/doc/refman/8.4/en/symbolic-links.html"}, refMySQLSec},
		std:  dbStd([]string{"CWE-59", "CWE-732"}, "CM-6", "AC-6"),
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			ok := mysqlSet(fs, "skip-symbolic-links") || anyMySQL(fs, "symbolic-links", isOff)
			ev := mysqlEvidence(fs, "skip_symbolic_links", "symbolic_links")
			if len(ev) == 0 {
				ev = []string{"no symbolic-links setting; the feature stays enabled on most builds"}
			}
			return !ok, ev
		},
	})

	registerDepth(depthRule{
		id: "NET-DB-015", title: "MySQL secure_file_priv Not Restricted", sev: check.Medium, cat: check.CatData,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:L/A:N",
		summary:   "secure_file_priv is not set, or is set to an empty value, so LOAD DATA and SELECT ... INTO OUTFILE can read and write anywhere the server process can.",
		rationale: "File import and export statements run with the database server's filesystem rights. Limiting them to one folder, or disabling them with NULL, stops an injected query from reading /etc files or dropping a web shell into the document root.",
		detection: "Parses the option files for secure_file_priv (or secure-file-priv) under [mysqld]. Fails when absent or set to an empty string. NULL or a folder path passes.",
		fix:       "Add  secure_file_priv = NULL  (no file operations) or  secure_file_priv = /var/lib/mysql-files  under [mysqld] and restart in a maintenance window.",
		verify:    "SHOW VARIABLES LIKE 'secure_file_priv';  should print NULL or the chosen folder.",
		patterns:  mysqlFiles, markers: mysqlMarkers,
		refs: []check.Ref{{Title: "MySQL 8.4 Reference Manual, secure_file_priv", URL: "https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_secure_file_priv"}, refMySQLSec},
		std:  dbStd([]string{"CWE-73", "CWE-250"}, "CM-6", "AC-6", "SI-10"),
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			vals := mysqlValues(fs, "secure_file_priv")
			bad := true
			for _, v := range vals {
				if strings.TrimSpace(v) != "" {
					bad = false
				}
			}
			ev := mysqlEvidence(fs, "secure_file_priv")
			if len(vals) == 0 {
				ev = []string{"secure_file_priv is not set in the option files"}
			}
			return bad, ev
		},
	})

	registerDepth(depthRule{
		id: "NET-DB-016", title: "MySQL Does Not Require Encrypted Client Connections", sev: check.Medium, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		summary:   "require_secure_transport is not ON, so clients may log in and query over plaintext TCP.",
		rationale: "Without the requirement, a client that is misconfigured or downgraded sends credentials and data in the clear across the network. The setting is harmless for Unix socket connections and makes TLS a server-side rule rather than a client choice. When bind-address keeps the server on loopback (127.0.0.1, ::1 or localhost) the plaintext path never leaves the machine and only a local root user could read it, so the check reports Pass with a note instead of a Medium finding; the Medium applies to servers reachable from the network.",
		detection: "Parses the option files for require_secure_transport under [mysqld]. Fails unless it is ON. Passes with a note when skip-networking is on (no TCP) or every bind-address value is a loopback address, since no network path exists to protect.",
		fix:       "Provision a server certificate (MySQL creates one by default), then add  require_secure_transport = ON  under [mysqld] and restart in a maintenance window. Test every application connection string first.",
		verify:    "SHOW VARIABLES LIKE 'require_secure_transport';  should print ON, and  a client that disables TLS (ssl-mode DISABLED) connecting to 127.0.0.1 should be refused.",
		patterns:  mysqlFiles, markers: mysqlMarkers,
		refs: []check.Ref{{Title: "MySQL 8.4 Reference Manual, Configuring MySQL to Use Encrypted Connections", URL: "https://dev.mysql.com/doc/refman/8.4/en/using-encrypted-connections.html"}, refNISTSC8},
		std:  check.Standards{CWE: []string{"CWE-319"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.2.2"}, NIST: []string{"SC-8", "SC-13"}, CISTopic: "Database transport encryption"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			if skipNetworking(fs) {
				return false, []string{"skip-networking is on; no TCP connections are accepted"}
			}
			var binds []string
			for _, v := range mysqlValues(fs, "bind-address") {
				binds = append(binds, strings.Split(v, ",")...) // MySQL 8 accepts a comma-separated list
			}
			if len(binds) > 0 && allLoopback(binds) {
				return false, append([]string{"bind-address is loopback only, so plaintext connections never leave this machine; TLS is still recommended before exposing the port"}, mysqlEvidence(fs, "bind_address", "require_secure_transport")...)
			}
			ok := false
			for _, v := range mysqlValues(fs, "require_secure_transport") {
				if isOn(v) {
					ok = true
				}
			}
			ev := mysqlEvidence(fs, "require_secure_transport")
			if len(ev) == 0 {
				ev = []string{"require_secure_transport is not set; the default is OFF"}
			}
			return !ok, ev
		},
	})

	registerDepth(depthRule{
		id: "NET-DB-017", title: "MySQL Error Log Not Configured", sev: check.Low, cat: check.CatLogging,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
		summary:   "log_error is not set, so server errors, failed logins and startup warnings go to the console or syslog without a dedicated, retained file.",
		rationale: "The error log is the first place to see authentication failures, crashes and plugin warnings. A named file with rotation makes those events available to incident response and to the audit checks that read it.",
		detection: "Parses the option files for log_error (or log-error) under [mysqld]. Fails when absent.",
		fix:       "Add  log_error = /var/log/mysql/error.log  under [mysqld], make the folder writable by the mysql user, and add a logrotate rule.",
		verify:    "SHOW VARIABLES LIKE 'log_error';  should print the file path.",
		patterns:  mysqlFiles, markers: mysqlMarkers,
		refs: []check.Ref{{Title: "MySQL 8.4 Reference Manual, The Error Log", URL: "https://dev.mysql.com/doc/refman/8.4/en/error-log.html"}, refMySQLOpts},
		std:  check.Standards{CWE: []string{"CWE-778"}, OWASP: []string{"A09:2021"}, ASVS: []string{"7.1.1"}, NIST: []string{"AU-2", "AU-12"}, CISTopic: "Database error logging"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			ev := mysqlEvidence(fs, "log_error")
			if !mysqlSet(fs, "log_error") {
				return true, []string{"log_error is not set in the option files"}
			}
			return false, ev
		},
	})

	registerDepth(depthRule{
		id: "NET-DB-018", title: "MySQL Resolves Client Host Names", sev: check.Low, cat: check.CatData,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
		summary:   "skip-name-resolve is not set, so grants that name hosts depend on DNS answers and every connection waits on a reverse lookup.",
		rationale: "Host-based grants that trust names can be satisfied by whoever controls DNS or the resolver path. With skip-name-resolve the server matches IP addresses only, which is both faster and not spoofable through DNS. Grants that use host names must be rewritten first.",
		detection: "Parses the option files for skip-name-resolve, skip_name_resolve or host_cache_size=0 under [mysqld]. Fails when none is present.",
		fix:       "Rewrite grants that use host names to IP addresses or '%', then add  skip-name-resolve  under [mysqld] and restart in a maintenance window.",
		verify:    "SHOW VARIABLES LIKE 'skip_name_resolve';  should print ON.",
		patterns:  mysqlFiles, markers: mysqlMarkers,
		refs: []check.Ref{{Title: "MySQL 8.4 Reference Manual, skip_name_resolve", URL: "https://dev.mysql.com/doc/refman/8.4/en/server-system-variables.html#sysvar_skip_name_resolve"}, refMySQLSec},
		std:  dbStd([]string{"CWE-350", "CWE-290"}, "CM-6", "IA-3"),
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			ok := anyMySQL(fs, "skip-name-resolve", func(v string) bool { return strings.TrimSpace(v) == "" || isOn(v) })
			if anyMySQL(fs, "skip-name-resolve", isOff) {
				ok = false
			}
			ev := mysqlEvidence(fs, "skip_name_resolve")
			if len(ev) == 0 {
				ev = []string{"skip-name-resolve is not set; the default is OFF"}
			}
			return !ok, ev
		},
	})

	// PostgreSQL
	registerDepth(depthRule{
		id: "NET-DB-019", title: "PostgreSQL Uses md5 or password Authentication", sev: check.Medium, cat: check.CatIdentity,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		summary:   "pg_hba.conf has active rules with the md5 or password method instead of scram-sha-256.",
		rationale: "The password method sends the password in clear text unless the connection is encrypted; md5 is a fast unsalted construction whose stored hashes work as passwords themselves (pass-the-hash) and which the PostgreSQL documentation describes as obsolete. SCRAM-SHA-256 fixes both.",
		detection: "Reads pg_hba.conf, ignores comments, and flags every rule whose method is md5 or password. NET-DB-004 already covers trust and open address ranges.",
		fix:       "Set  password_encryption = scram-sha-256  in postgresql.conf, have every role reset its password so a SCRAM verifier is stored, then change the pg_hba.conf methods to scram-sha-256 and reload.",
		verify:    "SELECT * FROM pg_hba_file_rules WHERE auth_method IN ('md5','password');  should return no rows.",
		patterns:  pgHBA, markers: pgMarkers,
		refs: []check.Ref{refPGAuth, {Title: "PostgreSQL, Password Authentication", URL: "https://www.postgresql.org/docs/current/auth-password.html"}, refNISTDigest},
		std:  check.Standards{CWE: []string{"CWE-328", "CWE-916"}, OWASP: []string{"A02:2021", "A07:2021"}, ASVS: []string{"2.4.1"}, NIST: []string{"IA-5", "IA-5(1)", "SC-13"}, CISTopic: "Database password hashing and authentication method"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			var ev []string
			// ReadConfigs keys by the first word ("host"), so rules are
			// rebuilt from the key/value pairs: key = type, value = rest.
			ev = nil
			for _, f := range fs {
				for _, typ := range []string{"host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc", "local"} {
					for _, rest := range f.Values[typ] {
						fields := strings.Fields(rest)
						if len(fields) == 0 {
							continue
						}
						method := strings.ToLower(fields[len(fields)-1])
						// Method may be followed by options such as clientcert=1.
						for i := len(fields) - 1; i >= 0; i-- {
							if !strings.Contains(fields[i], "=") {
								method = strings.ToLower(fields[i])
								break
							}
						}
						if method == "md5" || method == "password" {
							ev = append(ev, f.Path+": "+typ+" "+rest)
						}
					}
				}
			}
			return len(ev) > 0, ev
		},
		passMsg: "No pg_hba.conf rule uses md5 or password",
	})

	registerDepth(depthRule{
		id: "NET-DB-020", title: "PostgreSQL SSL Not Enabled", sev: check.Medium, cat: check.CatCrypto,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		summary:   "postgresql.conf does not set ssl = on, so TCP clients cannot encrypt their sessions and hostssl rules cannot apply.",
		rationale: "Without SSL every query and result crosses the network in the clear. Enabling it costs one certificate and lets pg_hba.conf require hostssl for remote clients. When listen_addresses keeps the server on loopback (the PostgreSQL default, localhost) the plaintext path never leaves the machine and only a local root user could read it, so the check reports Pass with a note instead of a Medium finding; the Medium applies to servers reachable from the network.",
		detection: "Reads postgresql.conf and flags ssl absent or off. Passes with a note when listen_addresses is empty (no TCP at all) or names only loopback addresses (localhost, 127.0.0.1, ::1), or when it is unset, since the PostgreSQL default is localhost.",
		fix:       "Install a certificate and key readable only by the postgres user, set  ssl = on , ssl_cert_file and ssl_key_file, reload, then change remote pg_hba.conf rules from host to hostssl.",
		verify:    "SHOW ssl;  should print on, and  psql \"sslmode=require host=127.0.0.1\"  should connect.",
		patterns:  pgConf, markers: pgMarkers,
		refs: []check.Ref{refPGSSL, refNISTSC8},
		std:  check.Standards{CWE: []string{"CWE-319"}, OWASP: []string{"A02:2021"}, ASVS: []string{"9.2.2"}, NIST: []string{"SC-8", "SC-13"}, CISTopic: "Database transport encryption"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			la, ok := pgValue(fs, "listen_addresses")
			if ok && la == "" {
				return false, []string{"listen_addresses is empty; no TCP connections are accepted"}
			}
			if !ok {
				return false, []string{"listen_addresses is not set; the PostgreSQL default is localhost, so plaintext connections never leave this machine; enable ssl before exposing the port"}
			}
			if allLoopback(strings.Split(la, ",")) {
				return false, []string{"listen_addresses = " + la + " is loopback only, so plaintext connections never leave this machine; enable ssl before exposing the port"}
			}
			v, ok := pgValue(fs, "ssl")
			if !ok {
				return true, []string{"ssl is not set; the default is off"}
			}
			return !isOn(v), evidence(fs, "ssl")
		},
	})

	registerDepth(depthRule{
		id: "NET-DB-021", title: "PostgreSQL Connection Logging Off", sev: check.Low, cat: check.CatLogging,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
		summary:   "log_connections and log_disconnections are off, so successful logins leave no record.",
		rationale: "Failed logins are logged by default, but successful ones are not. Knowing which role connected from where and for how long is the base evidence for spotting credential misuse and for any later investigation.",
		detection: "Reads postgresql.conf and flags log_connections not on. log_disconnections is reported as evidence.",
		fix:       "Set  log_connections = on  and  log_disconnections = on  in postgresql.conf and reload. On PostgreSQL 18 and newer, log_connections accepts a list such as  receipt,authentication,authorization .",
		verify:    "SHOW log_connections;  should print on (or a non-empty list).",
		patterns:  pgConf, markers: pgMarkers,
		refs: []check.Ref{refPGLog},
		std:  check.Standards{CWE: []string{"CWE-778"}, OWASP: []string{"A09:2021"}, ASVS: []string{"7.1.3"}, NIST: []string{"AU-2", "AU-12", "AC-2(4)"}, CISTopic: "Database connection logging"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			v, ok := pgValue(fs, "log_connections")
			ev := evidence(fs, "log_connections", "log_disconnections")
			if !ok {
				return true, []string{"log_connections is not set; the default is off"}
			}
			bad := isOff(v) || v == ""
			return bad, ev
		},
	})

	registerDepth(depthRule{
		id: "NET-DB-022", title: "PostgreSQL Password Encryption Not SCRAM", sev: check.Medium, cat: check.CatIdentity,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N",
		summary:   "password_encryption is set to md5, so new and changed passwords are stored as md5 verifiers that work as pass-the-hash credentials.",
		rationale: "The stored md5 value is itself sufficient to authenticate, so a leaked catalog is a leaked set of passwords. SCRAM-SHA-256 stores a salted, iterated verifier that is not usable directly. PostgreSQL 14 and newer default to scram-sha-256; older clusters often carry an explicit md5 line.",
		detection: "Reads postgresql.conf and flags password_encryption = md5 (or on, the legacy alias). Absent passes on the assumption of the modern default and is noted as evidence.",
		fix:       "Set  password_encryption = scram-sha-256 , reload, and ask every role to reset its password so the verifier is regenerated. Then move pg_hba.conf to scram-sha-256 (NET-DB-019).",
		verify:    "SELECT rolname FROM pg_authid WHERE rolpassword LIKE 'md5%';  should return no rows after the resets.",
		patterns:  pgConf, markers: pgMarkers,
		refs: []check.Ref{{Title: "PostgreSQL, Password Authentication", URL: "https://www.postgresql.org/docs/current/auth-password.html"}, refPGConn, refNISTDigest},
		std:  check.Standards{CWE: []string{"CWE-916", "CWE-328"}, OWASP: []string{"A02:2021"}, ASVS: []string{"2.4.1"}, NIST: []string{"IA-5(1)", "SC-13"}, CISTopic: "Database password hashing"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			v, ok := pgValue(fs, "password_encryption")
			if !ok {
				return false, []string{"password_encryption is not set; PostgreSQL 14 and newer default to scram-sha-256"}
			}
			lv := strings.ToLower(v)
			return lv == "md5" || lv == "on" || lv == "true", evidence(fs, "password_encryption")
		},
	})

	// Redis
	registerDepth(depthRule{
		id: "NET-DB-023", title: "Redis Dangerous Commands Not Restricted", sev: check.Medium, cat: check.CatData,
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:L",
		summary:   "redis.conf neither renames nor disables CONFIG, FLUSHALL, FLUSHDB, DEBUG and KEYS, and no ACL user excludes the @dangerous category.",
		rationale: "An attacker who reaches Redis with any credential can wipe data with FLUSHALL, rewrite the configuration with CONFIG SET to write files (the classic path to a cron job or SSH key), or stall the server with KEYS *. Removing or renaming these for application users limits what a stolen credential can do.",
		detection: "Parses redis.conf for rename-command lines covering CONFIG, FLUSHALL, FLUSHDB, DEBUG and KEYS, or an ACL definition (user lines, or an aclfile) that excludes @dangerous or @admin. Fails when neither protection exists.",
		fix:       "Prefer ACLs on Redis 6 and newer:  user app on >secret ~app:* -@all +@read +@write -@dangerous . Otherwise add  rename-command FLUSHALL \"\"  (and the same for FLUSHDB, CONFIG, DEBUG, KEYS) and restart.",
		verify:    "redis-cli -a <secret> ACL LIST  or  redis-cli CONFIG GET dir  should be refused for the application user.",
		patterns:  redisFiles, markers: redisMarkers,
		refs: []check.Ref{refRedisSec, refRedisACL},
		std:  check.Standards{CWE: []string{"CWE-250", "CWE-269"}, OWASP: []string{"A01:2021", "A05:2021"}, ASVS: []string{"14.1.3"}, NIST: []string{"AC-6", "CM-7"}, CISTopic: "Data store administrative command restriction"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			renamed := map[string]bool{}
			for _, v := range values(fs, "rename-command") {
				f := strings.Fields(strings.ToLower(v))
				if len(f) >= 1 {
					renamed[f[0]] = true
				}
			}
			allRenamed := renamed["config"] && renamed["flushall"] && renamed["flushdb"]
			aclRestricts := false
			for _, v := range values(fs, "user") {
				lv := strings.ToLower(v)
				if strings.Contains(lv, "-@dangerous") || strings.Contains(lv, "-@admin") || (strings.Contains(lv, "-@all") && !strings.Contains(lv, "+@all")) {
					aclRestricts = true
				}
			}
			if len(values(fs, "aclfile")) > 0 {
				aclRestricts = true // the ACL file is owned by the administrator; its content is not read here
			}
			ev := evidence(fs, "rename-command", "user", "aclfile")
			if len(ev) == 0 {
				ev = []string{"no rename-command, user or aclfile directive"}
			}
			return !(allRenamed || aclRestricts), ev
		},
	})
}

// skipNetworking reports whether the option files turn TCP off: a bare
// skip-networking line, or skip-networking set to an on value.
func skipNetworking(fs []collect.ConfigFile) bool {
	for _, v := range mysqlValues(fs, "skip-networking") {
		if strings.TrimSpace(v) == "" || isOn(v) {
			return true
		}
	}
	return false
}

// allLoopback reports whether every address in the list is a loopback
// address (127.0.0.1, any 127.x, ::1 or localhost). An empty list is not
// loopback: it means the server default, which differs per service.
func allLoopback(addrs []string) bool {
	if len(addrs) == 0 {
		return false
	}
	for _, a := range addrs {
		a = strings.ToLower(strings.Trim(strings.TrimSpace(a), `'"`))
		if a == "localhost" || a == "::1" || strings.HasPrefix(a, "127.") || a == "::ffff:127.0.0.1" {
			continue
		}
		return false
	}
	return true
}
