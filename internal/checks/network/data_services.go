package network

import (
	"context"
	"fmt"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/checks/collect"
	"github.com/openvapt/openvapt/internal/sys"
)

type configRule struct {
	id, title, summary, rationale, detection, fix, verify, cvss string
	severity                                                    check.Severity
	patterns                                                    []string
	ref                                                         check.Ref
	evaluate                                                    func([]collect.ConfigFile) (bool, []string)
}

func values(fs []collect.ConfigFile, keys ...string) []string {
	var out []string
	for _, f := range fs {
		for _, k := range keys {
			out = append(out, f.Values[strings.ToLower(k)]...)
		}
	}
	return out
}
func hasValue(fs []collect.ConfigFile, want func(string) bool, keys ...string) bool {
	for _, v := range values(fs, keys...) {
		if want(strings.ToLower(strings.TrimSpace(v))) {
			return true
		}
	}
	return false
}
func anyIncomplete(fs []collect.ConfigFile) bool {
	for _, f := range fs {
		if !f.Complete {
			return true
		}
	}
	return false
}
func evidence(fs []collect.ConfigFile, keys ...string) []string {
	var out []string
	for _, f := range fs {
		for _, k := range keys {
			for _, v := range f.Values[strings.ToLower(k)] {
				out = append(out, fmt.Sprintf("%s: %s = %s", f.Path, k, v))
			}
		}
	}
	return out
}

func registerConfig(r configRule) {
	check.Register(&check.Check{ID: r.id, Title: r.title, Domain: check.DomainNetwork, Severity: r.severity, Category: check.CatData, Effort: check.EffortLow, CVSS: r.cvss,
		Summary: r.summary, Rationale: r.rationale, Detection: r.detection, Fix: r.fix, Verify: r.verify, Refs: []check.Ref{r.ref},
		Standards: check.Standards{CWE: []string{"CWE-16", "CWE-284"}, OWASP: []string{"A05:2021"}, NIST: []string{"AC-3", "CM-6", "SC-7"}, CISTopic: "Secure data service configuration"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			fs := collect.ReadConfigs(ctx, s, r.patterns...)
			if len(fs) == 0 {
				return []check.Result{check.SkipR(strings.Join(r.patterns, ", "), "Service configuration was not found")}
			}
			bad, ev := r.evaluate(fs)
			if bad {
				return []check.Result{check.FailR(fs[0].Path, r.summary, ev...)}
			}
			if anyIncomplete(fs) {
				return []check.Result{check.IncompleteR(fs[0].Path, "Configuration input was truncated; a secure result cannot be established")}
			}
			return []check.Result{check.PassR(fs[0].Path, "Required security settings are present")}
		},
	})
}

func init() {
	yes := func(v string) bool { return v == "yes" || v == "true" || v == "on" || v == "1" }
	no := func(v string) bool { return v == "no" || v == "false" || v == "off" || v == "0" }
	registerConfig(configRule{
		"NET-DB-002",
		"Redis Authentication and Network Binding",
		"Redis lacks protected mode, authentication, or a loopback-only bind.",
		"An unauthenticated network-reachable Redis instance can disclose or alter data and may permit dangerous administrative operations.",
		"Parses redis.conf for protected-mode, requirepass or ACL users, and bind. It does not connect or authenticate.",
		"Set protected-mode yes, configure ACL users with strong secrets, bind to 127.0.0.1 and ::1, and restrict remote access with a firewall.",
		"Review redis-server --test-memory only for health, then inspect the effective configuration and listening socket after reload.",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		check.Critical,
		[]string{"/etc/redis/redis.conf", "/etc/redis.conf"},
		check.Ref{Title: "Redis Security", URL: "https://redis.io/docs/latest/operate/oss_and_stack/management/security/"},
		func(fs []collect.ConfigFile) (bool, []string) {
			bad := !hasValue(fs, yes, "protected-mode") || len(values(fs, "requirepass", "user")) == 0 || !hasValue(fs, func(v string) bool { return strings.Contains(v, "127.0.0.1") && !strings.Contains(v, "0.0.0.0") }, "bind")
			return bad, evidence(fs, "protected-mode", "bind", "user")
		}})
	registerConfig(configRule{
		"NET-DB-003",
		"MongoDB Authorization and Network Binding",
		"MongoDB authorization is disabled or it binds beyond loopback.",
		"MongoDB without authorization or with broad exposure can permit unauthenticated database access.",
		"Parses mongod configuration for security.authorization and net.bindIp.",
		"Set security.authorization to enabled and net.bindIp to 127.0.0.1, then allow only approved clients through a controlled network path.",
		"Run mongod --config <file> --configExpand none in a maintenance workflow and confirm port 27017 is loopback-only.",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		check.Critical,
		[]string{"/etc/mongod.conf", "/etc/mongodb.conf"},
		check.Ref{Title: "MongoDB Security Checklist", URL: "https://www.mongodb.com/docs/manual/administration/security-checklist/"},
		func(fs []collect.ConfigFile) (bool, []string) {
			bad := !hasValue(fs, func(v string) bool { return v == "enabled" }, "authorization", "security.authorization") || !hasValue(fs, func(v string) bool { return v == "127.0.0.1" || v == "localhost" }, "bindip", "net.bindip")
			return bad, evidence(fs, "authorization", "bindip")
		}})
	registerConfig(configRule{
		"NET-DB-004",
		"PostgreSQL Trust and Broad Client Access",
		"PostgreSQL accepts trust authentication or unrestricted client networks.",
		"Trust authentication and all-address client rules can allow database access without a password from untrusted networks.",
		"Reads postgresql.conf and pg_hba.conf, flags listen_addresses '*' or 0.0.0.0, trust methods, and 0.0.0.0/0 or ::/0 client ranges.",
		"Bind PostgreSQL to required interfaces only and replace trust or unrestricted pg_hba.conf rules with narrow CIDRs and scram-sha-256.",
		"Run pg_ctl reload through normal operations, then use pg_hba_file_rules and ss -tlnp to verify the effective rules.",
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		check.Critical,
		[]string{"/etc/postgresql/*/main/postgresql.conf", "/etc/postgresql/*/main/pg_hba.conf", "/var/lib/pgsql/data/pg_hba.conf"},
		check.Ref{Title: "PostgreSQL Client Authentication", URL: "https://www.postgresql.org/docs/current/client-authentication.html"},
		func(fs []collect.ConfigFile) (bool, []string) {
			var ev []string
			bad := false
			for _, f := range fs {
				raw := strings.ToLower(strings.Join(flatten(f.Values), " "))
				if strings.Contains(raw, "0.0.0.0/0") || strings.Contains(raw, "::/0") || strings.Contains(raw, " trust") || hasValue([]collect.ConfigFile{f}, func(v string) bool { return strings.Contains(v, "*") || strings.Contains(v, "0.0.0.0") }, "listen_addresses") {
					bad = true
					ev = append(ev, f.Path+": broad or trust rule detected")
				}
			}
			return bad, ev
		}})
	registerConfig(configRule{
		"NET-DB-005",
		"MySQL or MariaDB Unsafe Network Options",
		"MySQL or MariaDB enables local file loading, skips grants, or listens broadly with networking enabled.",
		"These options can bypass authorization, expand file access, or expose the database to untrusted networks.",
		"Parses MySQL and MariaDB option files for local_infile, skip-grant-tables, skip-networking, and bind-address.",
		"Disable local_infile and skip-grant-tables. Bind to 127.0.0.1 or enable skip-networking when TCP access is unnecessary.",
		"Inspect SHOW VARIABLES through an approved administrator session and confirm the listening address locally.",
		"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		check.High,
		[]string{"/etc/mysql/my.cnf", "/etc/mysql/mysql.conf.d/mysqld.cnf", "/etc/my.cnf"},
		check.Ref{Title: "MySQL Server Security Guidelines", URL: "https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html"},
		func(fs []collect.ConfigFile) (bool, []string) {
			bad := hasValue(fs, yes, "local_infile", "mysqld.local_infile") || len(values(fs, "skip-grant-tables", "mysqld.skip-grant-tables")) > 0 || (!hasValue(fs, yes, "skip-networking", "mysqld.skip-networking") && hasValue(fs, func(v string) bool { return v == "0.0.0.0" || v == "*" }, "bind-address", "mysqld.bind-address"))
			return bad, evidence(fs, "local_infile", "skip-grant-tables", "skip-networking", "bind-address")
		}})
	registerConfig(configRule{
		id:        "NET-DB-006",
		title:     "Memcached UDP or Broad Listen Address",
		summary:   "Memcached enables UDP or listens on a non-loopback address.",
		rationale: "Unauthenticated Memcached exposure can disclose cached data and UDP mode has been abused for amplification attacks.",
		detection: "Parses memcached configuration for -U or UDP_PORT and -l or listen address.",
		fix:       "Set UDP_PORT=0 or -U 0 and bind with -l 127.0.0.1. Use a firewall for any explicitly required clients.",
		verify:    "Confirm ss -ltnup shows Memcached only on loopback and no UDP port 11211.",
		cvss:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		severity:  check.High,
		patterns:  []string{"/etc/memcached.conf", "/etc/sysconfig/memcached"},
		ref:       check.Ref{Title: "memcached Configuration", URL: "https://docs.memcached.org/serverguide/configuring/"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			raw := strings.ToLower(strings.Join(flattenValues(fs), " "))
			bad := strings.Contains(raw, "-u 11211") || strings.Contains(raw, "udp_port=11211") || !strings.Contains(raw, "127.0.0.1")
			return bad, []string{"Memcached network options reviewed"}
		}})
	registerConfig(configRule{
		id:        "NET-DB-007",
		title:     "Elasticsearch Security and Network Binding",
		summary:   "Elasticsearch security is disabled or network.host is broadly reachable.",
		rationale: "An exposed Elasticsearch cluster without authentication can disclose, alter, or delete indexed data.",
		detection: "Parses elasticsearch.yml for xpack.security.enabled and network.host.",
		fix:       "Set xpack.security.enabled true, bind network.host to loopback or an approved private interface, require TLS, and filter access.",
		verify:    "Use the local node configuration API with approved credentials and confirm port 9200 is not broadly exposed.",
		cvss:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		severity:  check.Critical,
		patterns:  []string{"/etc/elasticsearch/elasticsearch.yml"},
		ref:       check.Ref{Title: "Elastic Security Minimal Setup", URL: "https://www.elastic.co/guide/en/elasticsearch/reference/current/security-minimal-setup.html"},
		evaluate: func(fs []collect.ConfigFile) (bool, []string) {
			bad := !hasValue(fs, yes, "xpack.security.enabled") || hasValue(fs, func(v string) bool { return v == "0.0.0.0" || v == "_site_" || v == "_global_" }, "network.host")
			return bad, evidence(fs, "xpack.security.enabled", "network.host")
		}})
	_ = no
}

func flatten(m map[string][]string) []string {
	var out []string
	for k, v := range m {
		for _, x := range v {
			out = append(out, k+" "+x)
		}
	}
	return out
}
func flattenValues(fs []collect.ConfigFile) []string {
	var out []string
	for _, f := range fs {
		out = append(out, flatten(f.Values)...)
	}
	return out
}
