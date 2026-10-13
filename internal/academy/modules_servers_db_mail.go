package academy

// Practitioner modules for the web server, database, mail and DNS hardening
// checks (WEB-NGX, WEB-APA, NET-DB-014 to NET-DB-023, NET-MAIL, NET-DNS).
// Registered from init so no other file's module slice is touched.

func init() {
	Modules = append(Modules, serversDBMail...)
	for k, v := range serversGlossary {
		Glossary[k] = v
	}
}

var serversGlossary = map[string]string{
	"Cipher Suite":             "The named combination of key exchange, authentication, encryption and integrity algorithms a TLS connection agrees on; weak suites let recorded traffic be decrypted.",
	"OCSP Stapling":            "The web server fetching a signed, time-limited statement that its certificate is not revoked and attaching it to the TLS handshake, so browsers need not ask the certificate authority.",
	"Web Application Firewall": "A filter in front of a web application that inspects requests against rules and blocks or logs attacks; a defence-in-depth layer, not a substitute for fixing the application.",
	"SCRAM-SHA-256":            "A password authentication method that stores a salted, iterated verifier and proves knowledge of the password without sending it; the PostgreSQL default since version 14.",
	"DNSSEC":                   "Digital signatures on DNS records that let a resolver verify answers came from the zone owner and were not altered in transit.",
	"STARTTLS":                 "An extension by which a plaintext mail session upgrades to TLS; opportunistic unless the server requires it.",
}

var serversDBMail = []Module{
	{
		ID: "P18", Title: "Web Server Hardening: nginx and Apache", Level: Practitioner, Minutes: 30,
		Summary: "Reading nginx.conf and apache2.conf the way an assessor does: the dozen directives that decide what a server reveals, which TLS it speaks, and which files it will hand out.",
		Objectives: []string{
			"Find the effective value of a directive across nginx.conf, conf.d, sites-enabled and Apache's Include tree.",
			"Explain why banner hiding, directory listing and TRACE are low-cost fixes worth making.",
			"Apply the Mozilla intermediate TLS profile and OCSP stapling to both servers.",
			"Deny dot-prefixed paths so repository and environment files are never served.",
		},
		Sections: []Section{
			{"Where the Configuration Really Lives", []string{
				"nginx reads one file, nginx.conf, and follows every include directive; Debian puts sites in sites-enabled and fragments in conf.d. Apache reads apache2.conf (Debian) or httpd.conf (RHEL) and follows Include and IncludeOptional. A directive set in a fragment can override the main file, so the assessor's view is the merged tree, which nginx -T and apachectl -t -D DUMP_CONFIG print. OpenVAPT builds the same merged view from the files, following includes only under the server's own configuration folder.",
				"The configuration view complements the live probes in WEB-HDR and WEB-EXP. A probe sees one response; the file shows the rule and the line to fix, and it finds a weak setting before a site is published.",
			}},
			{"Banners, Listings and Methods", []string{
				"server_tokens off in nginx and ServerTokens Prod with ServerSignature Off in Apache drop the version from the Server header and error pages. Hiding the version does not fix old software, but there is no reason to publish it (OWASP WSTG-INFO-02). autoindex on and Options Indexes turn folders without an index page into file listings. Debian's default Apache block for /var/www enables Indexes, so a fresh install lists uploads until someone changes it. TraceEnable Off removes an HTTP method that echoes request headers, including cookies, and that nothing legitimate uses.",
				"AllowOverride All lets any .htaccess file under the document root change handlers, options and access rules. Combined with an upload bug, that is how an image becomes a PHP script. AllowOverride None, or a short explicit list such as FileInfo Indexes Limit, keeps those decisions in root-owned configuration.",
			}},
			{"TLS the Mozilla Way", []string{
				"TLS 1.0 and 1.1 are deprecated by RFC 8996. nginx needs ssl_protocols TLSv1.2 TLSv1.3; Apache needs SSLProtocol -all +TLSv1.2 +TLSv1.3, because its default (all -SSLv3) still allows the old versions. The cipher list should be the short Mozilla intermediate set: ECDHE key exchange, AES-GCM or ChaCha20, nothing with RC4, DES, 3DES, MD5, NULL, export or anonymous suites. Both guidelines now set ssl_prefer_server_ciphers off and SSLHonorCipherOrder off, since every listed suite is strong and the client knows its own hardware best.",
				"OCSP stapling (ssl_stapling on; SSLUseStapling On) lets the server attach a fresh revocation status to the handshake, which is faster and stops browsers telling the certificate authority which sites a user visits. The Mozilla profiles also turn nginx session tickets off, because a ticket key that never rotates weakens forward secrecy. The Mozilla SSL Configuration Generator produces a full configuration block for either server; paste it rather than typing cipher names.",
			}},
			{"Dot Files and Limits", []string{
				"A .git folder rebuilds the source and its history; a .env file holds the database password. Debian's Apache default protects only .ht* files. One rule per server covers the whole class: nginx location ~ /\\. { deny all; } with a more specific location for /.well-known/ above it; Apache <DirectoryMatch \"/\\.(git|svn|hg)\"> and <FilesMatch \"^\\.(env|git)\"> with Require all denied. This also protects files deployed by mistake next year.",
				"client_max_body_size and limit_req_zone in nginx bound what one client can upload and how fast it can hit a login page. ModSecurity with the OWASP Core Rule Set, or mod_evasive, adds request filtering to Apache. These are informational in OpenVAPT because the right numbers depend on the application; a filter that is never tuned breaks sites, and one that is never deployed blocks nothing.",
			}},
		},
		KeyTerms:      []string{"Cipher Suite", "OCSP Stapling", "Directory Listing", "Web Application Firewall", "TLS", "Fingerprinting"},
		RelatedChecks: []string{"WEB-NGX-", "WEB-APA-"},
		Lab: []string{
			"Run: openvapt demo --only WEB-NGX-,WEB-APA- --out p15 and, for each finding, write the exact line in nginx.conf or apache2.conf that fixes it.",
			"Compare /etc/nginx/nginx.conf and /etc/apache2/apache2.conf between the two labs (internal/lab/fixtures_servers_db_mail.go) and explain what each changed directive prevents.",
			"On a test machine: nginx -T | grep -nE 'server_tokens|ssl_protocols|autoindex'  and  apachectl -t -D DUMP_CONFIG | grep -nE 'ServerTokens|SSLProtocol|Options' ; find the effective value and the file it came from.",
			"Generate an intermediate profile for your server version at the Mozilla SSL Configuration Generator and list every directive it sets that your current configuration lacks.",
		},
		Quiz: []Question{
			{"Apache has SSLEngine on but no SSLProtocol line. Which versions does it accept?", []string{"TLS 1.2 and 1.3 only", "Everything except SSLv3, so TLS 1.0 and 1.1 too", "TLS 1.3 only"}, 1, "The Apache default is all -SSLv3, which still allows the deprecated versions."},
			{"Why does the Mozilla intermediate profile set ssl_prefer_server_ciphers off?", []string{"It is faster for the server", "Every suite in the list is strong, so the client may pick the one its hardware handles best", "nginx requires it"}, 1, "Server preference mattered when lists still contained weak suites."},
			{"What does AllowOverride All let a .htaccess file do?", []string{"Nothing beyond redirects", "Change handlers, options and access rules for that folder", "Change the server's TLS certificate"}, 1, "Overrides move security decisions into files under the document root."},
			{"Which single rule stops nginx serving .git, .env and .svn under any site?", []string{"autoindex off", "location ~ /\\. { deny all; }", "server_tokens off"}, 1, "A deny for every dot-prefixed path segment covers the whole class."},
		},
		Refs: []Ref{{"Mozilla, Server Side TLS guidelines", "https://wiki.mozilla.org/Security/Server_Side_TLS"}, {"Mozilla SSL Configuration Generator", "https://ssl-config.mozilla.org/"}, {"Apache HTTP Server, Security Tips", "https://httpd.apache.org/docs/2.4/misc/security_tips.html"}, {"nginx documentation, ngx_http_ssl_module", "https://nginx.org/en/docs/http/ngx_http_ssl_module.html"}, {"NIST SP 800-52 Rev. 2, Guidelines for TLS Implementations", "https://csrc.nist.gov/pubs/sp/800/52/r2/final"}, {"OWASP Web Security Testing Guide, Configuration and Deployment Management Testing", "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/"}},
	},
	{
		ID: "P19", Title: "Database, Mail and DNS Hardening", Level: Practitioner, Minutes: 30,
		Summary: "Beyond binding and authentication: the option-file settings that limit what a compromised database credential can do, make mail and database traffic encrypted by rule, and keep DNS honest.",
		Objectives: []string{
			"Read MySQL, PostgreSQL and Redis option files and name the setting behind each finding.",
			"Explain why secure_file_priv, symbolic links and Redis administrative commands turn a database credential into a server compromise.",
			"Move PostgreSQL from md5 to SCRAM-SHA-256 without locking users out.",
			"Harden Postfix and Dovecot TLS, disable VRFY, and hide the BIND version while keeping DNSSEC validation on.",
		},
		Sections: []Section{
			{"When a Database Credential Becomes a Shell", []string{
				"A database server runs as its own user with read and write access to its data folder, and sometimes more. MySQL's LOAD DATA and SELECT ... INTO OUTFILE read and write files with that access; secure_file_priv confines them to one folder or, set to NULL, disables them. With symbolic links allowed, a table can point outside the data directory. Redis CONFIG SET can change the directory and file name it saves to, which is the classic route from an exposed Redis to a cron job or an SSH key; FLUSHALL wipes every key in one command. Renaming those commands, or better an ACL that denies @dangerous for application users, limits what a stolen credential can do.",
				"These are configuration-file signals only. OpenVAPT never connects to the database, so it cannot see anonymous users or a leftover test database; check those with the vendor's own tools under administrator credentials.",
			}},
			{"Passwords and Transport", []string{
				"PostgreSQL's md5 method stores a value that works as the password itself, so a copied catalog is a copied set of credentials; the password method sends the password in the clear unless the session is encrypted. SCRAM-SHA-256 fixes both and is the default since PostgreSQL 14. Migrating safely means setting password_encryption first, having every role reset its password so a SCRAM verifier exists, and only then changing the pg_hba.conf methods.",
				"ssl = on in PostgreSQL and require_secure_transport = ON in MySQL make encryption a server rule rather than a client option. skip-name-resolve in MySQL stops grants depending on DNS answers that an attacker on the path can forge. log_error and log_connections turn silent events, including every successful login, into evidence.",
			}},
			{"Mail: Offer TLS, Require TLS, Say Nothing Extra", []string{
				"Postfix smtpd_tls_security_level = may with a real certificate is what other mail servers expect; none means every message arrives in the clear. The default protocol list still admits TLS 1.0 and 1.1, so set smtpd_tls_protocols and smtpd_tls_mandatory_protocols to >=TLSv1.2. disable_vrfy_command = yes stops address enumeration. Dovecot ssl = required refuses any command before TLS, which completes the plaintext-authentication control: with ssl = yes a client may still keep the whole session unencrypted.",
			}},
			{"DNS: Hide the Version, Validate the Answers", []string{
				"A CHAOS query for version.bind returns the exact BIND release unless options sets a version string. DNSSEC validation (dnssec-validation auto) lets a recursive resolver reject forged answers for signed zones; BIND 9.16 and newer enable it by default, so an explicit no is a deliberate weakening and the one state OpenVAPT flags.",
			}},
		},
		KeyTerms:      []string{"SCRAM-SHA-256", "DNSSEC", "STARTTLS", "Least Privilege", "Open Relay", "Hardening"},
		RelatedChecks: []string{"NET-DB-014", "NET-DB-015", "NET-DB-016", "NET-DB-017", "NET-DB-018", "NET-DB-019", "NET-DB-020", "NET-DB-021", "NET-DB-022", "NET-DB-023", "NET-MAIL-", "NET-DNS-"},
		Lab: []string{
			"Run: openvapt demo --only NET-DB-,NET-MAIL-,NET-DNS- --out p16 and group the findings into three buckets: limits what a credential can do, makes transport encrypted, produces evidence.",
			"Read /etc/mysql/conf.d/hardening.cnf, the PostgreSQL files and redis.conf in the hardened lab (internal/lab/fixtures_servers_db_mail.go) and write one sentence per line on what it prevents.",
			"Write the ordered steps to move a PostgreSQL 13 cluster from md5 to scram-sha-256 without locking out the application, and say what breaks if the order is wrong.",
			"On a test resolver: dig @127.0.0.1 version.bind txt chaos +short  and  dig @127.0.0.1 dnssec-failed.org a ; explain what each answer shows.",
		},
		Quiz: []Question{
			{"What does secure_file_priv = NULL do?", []string{"Disables password checks", "Disables file import and export statements entirely", "Deletes the data directory"}, 1, "NULL turns off LOAD DATA and INTO OUTFILE file access."},
			{"Why is a PostgreSQL md5 verifier worse than it sounds?", []string{"It is slow", "The stored value itself authenticates, so a leaked catalog is a leaked password set", "It only works over IPv4"}, 1, "md5 verifiers are usable directly; SCRAM verifiers are not."},
			{"What is the correct order when moving to SCRAM-SHA-256?", []string{"Change pg_hba.conf first, then passwords", "Set password_encryption, reset every password, then change pg_hba.conf", "Reinstall PostgreSQL"}, 1, "Roles must have a SCRAM verifier before pg_hba.conf demands one."},
			{"Dovecot has ssl = yes. Can a client read mail without TLS?", []string{"No, yes means mandatory", "Yes, TLS is offered but not required; ssl = required refuses plaintext sessions", "Only on port 993"}, 1, "yes is opportunistic; required is the enforcing value."},
		},
		Refs: []Ref{{"MySQL 8.4 Reference Manual, Security Guidelines", "https://dev.mysql.com/doc/refman/8.4/en/security-guidelines.html"}, {"PostgreSQL, Password Authentication", "https://www.postgresql.org/docs/current/auth-password.html"}, {"Redis Security", "https://redis.io/docs/latest/operate/oss_and_stack/management/security/"}, {"Postfix TLS Support", "https://www.postfix.org/TLS_README.html"}, {"Dovecot SSL/TLS Configuration", "https://doc.dovecot.org/main/core/config/ssl.html"}, {"NIST SP 800-81 Rev. 2, Secure Domain Name System Deployment Guide", "https://csrc.nist.gov/pubs/sp/800/81/r2/final"}, {"NIST SP 800-177 Rev. 1, Trustworthy Email", "https://csrc.nist.gov/pubs/sp/800/177/r1/final"}},
	},
}
