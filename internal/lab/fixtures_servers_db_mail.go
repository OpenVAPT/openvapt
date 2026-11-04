package lab

import "github.com/openvapt/openvapt/internal/sys"

// Fixtures for the web server (WEB-NGX, WEB-APA), database depth
// (NET-DB-014 to NET-DB-023), mail (NET-MAIL) and DNS (NET-DNS) checks.
// The lab server runs both Apache and nginx so every check has a target.
// nginx carries no server_name, so it adds no website to the probe list.

func init() { Register(serversVulnerable, serversHardened) }

// appendFile adds lines to a file another fixture may already have created.
func appendFile(f *sys.Fake, path, lines string) {
	f.Files[path] = f.Files[path] + lines
}

func serversVulnerable(f *sys.Fake) {
	// nginx: version shown, listing on, old TLS, weak ciphers, no stapling,
	// no limits, dot files served.
	f.Files["/etc/nginx/nginx.conf"] = "user www-data;\nhttp {\n    include /etc/nginx/conf.d/*.conf;\n    ssl_protocols TLSv1 TLSv1.1 TLSv1.2;\n    ssl_ciphers ALL:RC4-SHA:DES-CBC3-SHA;\n    ssl_prefer_server_ciphers on;\n    server {\n        listen 443 ssl;\n        ssl_certificate /etc/ssl/certs/shop.pem;\n        root /var/www/shop;\n        autoindex on;\n    }\n}\n"
	f.Files["/etc/nginx/conf.d/tokens.conf"] = "server_tokens on;\n"

	// Apache: Debian-style layout with the stock weak defaults.
	f.Files["/etc/apache2/apache2.conf"] = "ServerRoot \"/etc/apache2\"\nIncludeOptional mods-enabled/*.load\nIncludeOptional mods-enabled/*.conf\nIncludeOptional conf-enabled/*.conf\nIncludeOptional sites-enabled/*.conf\n<Directory /var/www/>\n    Options Indexes FollowSymLinks\n    AllowOverride All\n</Directory>\nFileETag INode MTime Size\n<FilesMatch \"^\\.ht\">\n    Require all denied\n</FilesMatch>\n"
	f.Files["/etc/apache2/conf-enabled/security.conf"] = "ServerTokens OS\nServerSignature On\nTraceEnable On\n"
	f.Files["/etc/apache2/mods-enabled/ssl.conf"] = "SSLEngine on\nSSLProtocol all -SSLv2\nSSLCipherSuite ALL:!aNULL:RC4-SHA\nSSLHonorCipherOrder on\n"

	// Databases: nothing beyond the network binding fixtures, so every depth
	// setting is at its weak default. PostgreSQL carries an explicit md5.
	appendFile(f, "/etc/postgresql/16/main/postgresql.conf", "password_encryption = md5\n")
	appendFile(f, "/etc/postgresql/16/main/pg_hba.conf", "host all all 10.0.0.0/8 md5\n")

	// Mail and DNS.
	appendFile(f, "/etc/postfix/main.cf", "smtpd_tls_security_level = may\nsmtpd_tls_protocols = !SSLv2, !SSLv3\n")
	f.Files["/etc/dovecot/conf.d/10-ssl.conf"] = "ssl = yes\n"
	f.Files["/etc/bind/named.conf.options"] = "options { recursion yes; allow-transfer { any; }; dnssec-validation no; };\n"
}

func serversHardened(f *sys.Fake) {
	f.Files["/etc/nginx/nginx.conf"] = "user www-data;\nhttp {\n    include conf.d/*.conf;\n    server_tokens off;\n    ssl_protocols TLSv1.2 TLSv1.3;\n    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-CHACHA20-POLY1305;\n    ssl_prefer_server_ciphers off;\n    ssl_stapling on;\n    ssl_stapling_verify on;\n    ssl_session_tickets off;\n    client_max_body_size 8m;\n    limit_req_zone $binary_remote_addr zone=login:10m rate=10r/m;\n    server {\n        listen 443 ssl;\n        ssl_certificate /etc/ssl/certs/shop.pem;\n        root /var/www/shop;\n        location ^~ /.well-known/ { allow all; }\n        location ~ /\\. { deny all; access_log off; log_not_found off; }\n    }\n}\n"
	f.Files["/etc/nginx/conf.d/tokens.conf"] = "# nothing to override\n"

	f.Files["/etc/apache2/apache2.conf"] = "ServerRoot \"/etc/apache2\"\nIncludeOptional mods-enabled/*.load\nIncludeOptional mods-enabled/*.conf\nIncludeOptional conf-enabled/*.conf\nIncludeOptional sites-enabled/*.conf\n<Directory /var/www/>\n    Options -Indexes +FollowSymLinks\n    AllowOverride None\n</Directory>\nFileETag MTime Size\n<FilesMatch \"^\\.ht\">\n    Require all denied\n</FilesMatch>\n<DirectoryMatch \"/\\.(git|svn|hg)\">\n    Require all denied\n</DirectoryMatch>\n<FilesMatch \"^\\.(env|git)\">\n    Require all denied\n</FilesMatch>\n"
	f.Files["/etc/apache2/conf-enabled/security.conf"] = "ServerTokens Prod\nServerSignature Off\nTraceEnable Off\n"
	f.Files["/etc/apache2/mods-enabled/ssl.conf"] = "SSLEngine on\nSSLProtocol -all +TLSv1.2 +TLSv1.3\nSSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256\nSSLHonorCipherOrder off\nSSLUseStapling On\nSSLStaplingCache \"shmcb:logs/ssl_stapling(32768)\"\n"
	f.Files["/etc/apache2/mods-enabled/security2.load"] = "LoadModule security2_module /usr/lib/apache2/modules/mod_security2.so\n"

	f.Files["/etc/mysql/conf.d/hardening.cnf"] = "[mysqld]\nsymbolic-links=0\nsecure_file_priv=/var/lib/mysql-files\nrequire_secure_transport=ON\nlog_error=/var/log/mysql/error.log\nskip-name-resolve\n"
	appendFile(f, "/etc/postgresql/16/main/postgresql.conf", "ssl = on\nlog_connections = on\nlog_disconnections = on\npassword_encryption = scram-sha-256\n")
	appendFile(f, "/etc/redis/redis.conf", "rename-command CONFIG \"\"\nrename-command FLUSHALL \"\"\nrename-command FLUSHDB \"\"\n")

	appendFile(f, "/etc/postfix/main.cf", "smtpd_tls_security_level = may\nsmtpd_tls_chain_files = /etc/letsencrypt/live/mail/privkey.pem, /etc/letsencrypt/live/mail/fullchain.pem\nsmtpd_tls_protocols = >=TLSv1.2\nsmtpd_tls_mandatory_protocols = >=TLSv1.2\ndisable_vrfy_command = yes\n")
	f.Files["/etc/dovecot/conf.d/10-ssl.conf"] = "ssl = required\nssl_min_protocol = TLSv1.2\n"
	f.Files["/etc/bind/named.conf.options"] = "options { recursion no; allow-transfer { none; }; version \"not disclosed\"; dnssec-validation auto; };\n"
}
