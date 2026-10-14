package network

import (
	"context"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

// mysqlFlavor says which database server provides MySQL here, read from
// the MariaDB binary or option folder, the dpkg status file (installed
// entries only) and the allow-listed rpm -qa. major is the MySQL major
// version (5 for 5.7, 8 for 8.0 and 8.4); 0 when unknown.
type mysqlFlavor struct {
	mariadb bool
	major   int
	source  string
}

func (f mysqlFlavor) known() bool { return f.mariadb || f.major > 0 }

// modernMySQL is MySQL 8.0 or later, whose packaged defaults already
// disable symbolic links and restrict secure_file_priv.
func (f mysqlFlavor) modernMySQL() bool { return !f.mariadb && f.major >= 8 }

func (f mysqlFlavor) String() string {
	switch {
	case f.mariadb:
		return "MariaDB (" + f.source + ")"
	case f.major > 0:
		return "MySQL " + strconv.Itoa(f.major) + ".x (" + f.source + ")"
	}
	return "unknown server version"
}

func majorOf(v string) int {
	if _, after, ok := strings.Cut(v, ":"); ok {
		v = after
	}
	end := 0
	for end < len(v) && v[end] >= '0' && v[end] <= '9' {
		end++
	}
	n, _ := strconv.Atoi(v[:end])
	return n
}

func detectMySQLFlavor(ctx context.Context, s sys.System) mysqlFlavor {
	if _, err := s.Stat("/usr/sbin/mariadbd"); err == nil {
		return mysqlFlavor{mariadb: true, source: "/usr/sbin/mariadbd"}
	}
	if g, _ := s.Glob("/etc/mysql/mariadb.conf.d/*.cnf"); len(g) > 0 {
		return mysqlFlavor{mariadb: true, source: "/etc/mysql/mariadb.conf.d"}
	}
	if r, err := s.ReadFile(ctx, "/var/lib/dpkg/status"); err == nil {
		for _, block := range strings.Split(string(r.Data), "\n\n") {
			m := map[string]string{}
			for _, l := range strings.Split(block, "\n") {
				if k, v, ok := strings.Cut(l, ":"); ok && !strings.HasPrefix(l, " ") {
					m[strings.TrimSpace(k)] = strings.TrimSpace(v)
				}
			}
			if m["Status"] != "install ok installed" {
				continue
			}
			if f, ok := flavorFromPackage(m["Package"], m["Version"], "dpkg status"); ok {
				return f
			}
		}
	}
	if out, err := s.Run(ctx, "rpm", "-qa", "--qf", "%{NAME}\t%{EPOCHNUM}:%{VERSION}-%{RELEASE}\n"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if name, ver, ok := strings.Cut(l, "\t"); ok {
				if f, ok := flavorFromPackage(name, ver, "rpm"); ok {
					return f
				}
			}
		}
	}
	return mysqlFlavor{}
}

func flavorFromPackage(name, ver, src string) (mysqlFlavor, bool) {
	switch {
	case strings.HasPrefix(name, "mariadb-server"):
		return mysqlFlavor{mariadb: true, source: src + " " + name}, true
	case strings.HasPrefix(name, "mysql-server-core-"), strings.HasPrefix(name, "mysql-server-") && name[len("mysql-server-")] >= '0' && name[len("mysql-server-")] <= '9':
		// Debian and Ubuntu encode the series in the name: mysql-server-8.0.
		i := strings.LastIndex(name, "-")
		if m := majorOf(name[i+1:]); m > 0 {
			return mysqlFlavor{major: m, source: src + " " + name}, true
		}
	case name == "mysql-server", name == "mysql-community-server", name == "percona-server-server":
		if m := majorOf(ver); m > 0 {
			return mysqlFlavor{major: m, source: src + " " + name + " " + ver}, true
		}
	}
	return mysqlFlavor{}, false
}
