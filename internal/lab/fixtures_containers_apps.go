package lab

import (
	"io/fs"
	"net/http"
	"time"

	"github.com/openvapt/openvapt/internal/sys"
)

// Fixtures for the deeper container checks (HOST-CTR-005 and later), the
// application framework checks (WEB-APP), the deeper CMS checks (WEB-CMS-012
// and later) and the cross-cutting hygiene checks (HOST-SEC, HOST-CRON,
// HOST-SSH-013, HOST-USR-008 to 010). The vulnerable shop also runs a
// Laravel storefront, a Symfony CRM, a Rails back office, a Spring Boot API,
// a Flask report script and a Ghost blog the careless way; the hardened shop
// runs the same stack with the documented production settings. Values that
// look like secrets are placeholders and never reach a report.

const vulnDaemonJSON = `{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"],
 "insecure-registries": ["registry.example.test:5000"], "debug": true, "experimental": true,
 "seccomp-profile": "unconfined"}`

const hardDaemonJSON = `{"hosts": ["unix:///var/run/docker.sock"], "no-new-privileges": true, "icc": false,
 "userns-remap": "default", "live-restore": true, "log-driver": "json-file",
 "log-opts": {"max-size": "10m", "max-file": "3"}, "userland-proxy": false,
 "default-ulimits": {"nofile": {"Name": "nofile", "Hard": 65536, "Soft": 32768}, "nproc": {"Name": "nproc", "Hard": 4096, "Soft": 2048}}}`

const vulnHostConfig = `{"Privileged": true, "PidMode": "host", "NetworkMode": "host", "CapAdd": ["SYS_ADMIN"],
 "Binds": ["/var/run/docker.sock:/var/run/docker.sock", "/:/host"], "SecurityOpt": ["seccomp=unconfined", "apparmor=unconfined"],
 "ReadonlyRootfs": false, "Memory": 0, "PidsLimit": 0, "LogConfig": {"Type": "json-file", "Config": {}}}`

const hardHostConfig = `{"Privileged": false, "PidMode": "", "NetworkMode": "bridge", "CapAdd": null, "Binds": ["/srv/app/data:/data:ro"],
 "SecurityOpt": ["no-new-privileges"], "ReadonlyRootfs": true, "Memory": 536870912, "PidsLimit": 256,
 "LogConfig": {"Type": "json-file", "Config": {"max-size": "10m", "max-file": "3"}}}`

func init() {
	Register(containersAppsVulnerable, containersAppsHardened)
}

func containersAppsVulnerable(f *sys.Fake) {
	// Docker: debug daemon, unconfined containers, world-writable socket,
	// deploy in the docker group, containerd on TCP, no content trust.
	f.Files["/etc/docker/daemon.json"] = vulnDaemonJSON
	f.Files["/var/lib/docker/containers/"+ctrID+"/hostconfig.json"] = vulnHostConfig
	f.Files["/var/lib/docker/containers/"+ctrID+"/config.v2.json"] = `{"Name": "/shop-db", "Config": {"User": ""}}`
	f.Infos["/var/run/docker.sock"] = sys.FileInfo{Path: "/var/run/docker.sock", Mode: fs.ModeSocket | 0o666, UID: 0, GID: 0}
	f.Files["/etc/containerd/config.toml"] = "version = 2\n[grpc]\n  address = \"/run/containerd/containerd.sock\"\n  tcp_address = \"0.0.0.0:8888\"\n"

	// Accounts: a duplicate GID, deploy in the docker group, toor with no
	// shadow entry (base lab), a world-readable home.
	f.Files["/etc/group"] = "root:x:0:\nadm:x:4:\nstaff:x:4:deploy\ndocker:x:999:deploy\ndeploy:x:1000:\n"
	dir(f, "/home/deploy", 0o755)

	// Secrets in world-readable files, an unrestricted root key.
	file(f, "/etc/app/db.conf", "[database]\nhost=127.0.0.1\npassword=hunter2\n", 0o666)
	file(f, "/etc/backup/backup-key.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEplaceholder\n-----END RSA PRIVATE KEY-----\n", 0o644)
	f.Files["/var/www/shop/.env"] = "APP_KEY=base64:placeholder\nDB_PASSWORD=hunter2\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
	file(f, "/root/.ssh/authorized_keys", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCplaceholder root@laptop\n", 0o644)

	// Cron: the backup script is world-writable and PATH starts with a
	// world-writable folder.
	f.Files["/etc/crontab"] = "PATH=/opt/scripts:/usr/local/bin:/usr/bin:/bin\n" + f.Files["/etc/crontab"] + "0 4 * * * root backup-db --all\n"
	f.Infos["/usr/local/bin/backup.sh"] = sys.FileInfo{Path: "/usr/local/bin/backup.sh", Mode: 0o777, UID: 1000}
	dir(f, "/usr/local/bin", 0o755)
	dir(f, "/opt/scripts", 0o777)
	dir(f, "/usr/bin", 0o755)
	dir(f, "/bin", 0o755)

	// Laravel storefront: debug on, no key, world-readable .env, 777 folders,
	// a two-year-old composer.lock.
	file(f, "/srv/shop-laravel/.env", "APP_NAME=Shop\nAPP_ENV=local\nAPP_KEY=\nAPP_DEBUG=true\nDB_PASSWORD=hunter2\n", 0o644)
	dir(f, "/srv/shop-laravel/storage", 0o777)
	dir(f, "/srv/shop-laravel/bootstrap/cache", 0o777)
	f.Files["/srv/shop-laravel/composer.lock"] = `{"packages": []}`
	f.Infos["/srv/shop-laravel/composer.lock"] = sys.FileInfo{Path: "/srv/shop-laravel/composer.lock", Mode: 0o644, ModTime: time.Now().Add(-800 * 24 * time.Hour)}

	// Symfony CRM in dev, Rails back office with a readable master key and
	// no forced HTTPS, Spring Boot API with every actuator endpoint, Flask
	// report script with debug=True, Ghost blog on plain HTTP.
	file(f, "/srv/shop-crm/.env", "APP_ENV=dev\nAPP_DEBUG=1\nAPP_SECRET=hunter2\nDATABASE_URL=mysql://shop:hunter2@127.0.0.1:3306/crm\n", 0o644)
	file(f, "/srv/shop-rails/config/master.key", "hunter2hunter2hunter2hunter2\n", 0o644)
	file(f, "/srv/shop-rails/config/environments/production.rb", "Rails.application.configure do\n  config.force_ssl = false\nend\n", 0o644)
	file(f, "/opt/shop-api/application.properties", "server.port=8080\nmanagement.endpoints.web.exposure.include=*\nspring.datasource.password=hunter2\n", 0o644)
	file(f, "/srv/shop-reports/app.py", "from flask import Flask\napp = Flask(__name__)\n\nif __name__ == '__main__':\n    app.run(host='0.0.0.0', debug=True)\n", 0o644)
	file(f, "/srv/shop-blog/config.production.json", `{"url": "http://blog.example.test", "server": {"port": 2368, "host": "127.0.0.1"}, "database": {"client": "sqlite3"}}`, 0o644)

	// Web root: a .git folder, Drupal 8 with update.php open, Joomla 3,
	// Magento in developer mode, WordPress cron and author redirect.
	f.Files["/var/www/shop/.git/HEAD"] = "ref: refs/heads/main\n"
	f.Files["/var/www/shop/core/lib/Drupal.php"] = "<?php\nclass Drupal {\n  const VERSION = '8.5.0';\n}\n"
	file(f, "/var/www/shop/sites/intranet/settings.php", "<?php\n$databases['default']['default'] = ['password' => 'hunter2'];\n$settings['update_free_access'] = TRUE;\n", 0o640)
	f.Files["/var/www/shop/administrator/manifests/files/joomla.xml"] = "<extension type=\"file\"><name>files_joomla</name><version>3.9.0</version></extension>\n"
	f.Files["/var/www/shop/app/etc/env.php"] = "<?php\nreturn [\n  'MAGE_MODE' => 'developer',\n  'db' => ['connection' => ['default' => ['password' => 'hunter2']]],\n];\n"
	f.HTTPResp["https://"+site+"/wp-cron.php"] = sys.HTTPResponse{Status: 200, Header: http.Header{"Content-Type": {"text/html; charset=UTF-8"}}, Body: ""}
	f.HTTPResp["https://"+site+"/?author=1"] = sys.HTTPResponse{Status: 301, Header: http.Header{"Location": {"https://" + site + "/author/admin/"}}}
}

func containersAppsHardened(f *sys.Fake) {
	f.Files["/etc/docker/daemon.json"] = hardDaemonJSON
	f.Files["/var/lib/docker/containers/"+ctrID+"/hostconfig.json"] = hardHostConfig
	f.Files["/var/lib/docker/containers/"+ctrID+"/config.v2.json"] = `{"Name": "/shop-db", "Config": {"User": "1000:1000"}}`
	f.Infos["/var/run/docker.sock"] = sys.FileInfo{Path: "/var/run/docker.sock", Mode: fs.ModeSocket | 0o660, UID: 0, GID: 999}
	f.Files["/etc/containerd/config.toml"] = "version = 2\n[grpc]\n  address = \"/run/containerd/containerd.sock\"\n"
	f.Files["/etc/containers/containers.conf"] = "[containers]\nlabel = true\nseccomp_profile = \"/usr/share/containers/seccomp.json\"\n"
	file(f, "/etc/environment", "DOCKER_CONTENT_TRUST=1\n", 0o644)
	f.Files["/home/deploy/.config/docker/daemon.json"] = `{}`

	f.Files["/etc/group"] = "root:x:0:\nadm:x:4:\ndocker:x:999:\ndeploy:x:1000:\n"
	dir(f, "/home/deploy", 0o750)
	file(f, "/root/.ssh/authorized_keys", "from=\"203.0.113.0/24\",no-port-forwarding,no-agent-forwarding ssh-ed25519 AAAAC3NzaC1lZDI1NTE5placeholder admin\n", 0o600)

	f.Files["/etc/crontab"] = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n" + f.Files["/etc/crontab"]
	file(f, "/etc/cron.d/shop-backup", "0 3 * * * root /usr/local/sbin/shop-backup\n", 0o644)
	f.Infos["/usr/local/sbin/shop-backup"] = sys.FileInfo{Path: "/usr/local/sbin/shop-backup", Mode: 0o755, UID: 0}
	for _, d := range []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"} {
		dir(f, d, 0o755)
	}

	file(f, "/srv/shop-laravel/.env", "APP_NAME=Shop\nAPP_ENV=production\nAPP_KEY=base64:placeholder\nAPP_DEBUG=false\nDB_PASSWORD=hunter2\n", 0o640)
	dir(f, "/srv/shop-laravel/storage", 0o775)
	dir(f, "/srv/shop-laravel/bootstrap/cache", 0o775)
	f.Files["/srv/shop-laravel/composer.lock"] = `{"packages": []}`
	f.Infos["/srv/shop-laravel/composer.lock"] = sys.FileInfo{Path: "/srv/shop-laravel/composer.lock", Mode: 0o640, ModTime: time.Now().Add(-20 * 24 * time.Hour)}
	file(f, "/srv/shop-crm/.env", "APP_ENV=prod\nAPP_DEBUG=0\nAPP_SECRET=hunter2\n", 0o640)
	file(f, "/srv/shop-rails/config/master.key", "hunter2hunter2hunter2hunter2\n", 0o600)
	file(f, "/srv/shop-rails/config/environments/production.rb", "Rails.application.configure do\n  # config.force_ssl = false\n  config.force_ssl = true\nend\n", 0o644)
	file(f, "/opt/shop-api/application.properties", "server.port=8080\nmanagement.endpoints.web.exposure.include=health,info\nmanagement.server.port=9090\n", 0o640)
	file(f, "/srv/shop-reports/app.py", "import os\nfrom flask import Flask\napp = Flask(__name__)\n\nif __name__ == '__main__':\n    app.run(debug=os.environ.get('FLASK_DEBUG') == '1')\n", 0o644)
	file(f, "/srv/shop-blog/config.production.json", `{"url": "https://blog.example.test", "server": {"port": 2368, "host": "127.0.0.1"}, "database": {"client": "sqlite3"}}`, 0o640)

	f.Files["/var/www/shop/core/lib/Drupal.php"] = "<?php\nclass Drupal {\n  const VERSION = '11.1.0';\n}\n"
	file(f, "/var/www/shop/sites/default/settings.php", "<?php\n$databases['default']['default'] = ['password' => 'hunter2'];\n"+
		"$settings['trusted_host_patterns'] = ['^shop\\.example\\.test$'];\n$settings['update_free_access'] = FALSE;\n", 0o640)
	f.Files["/var/www/shop/administrator/manifests/files/joomla.xml"] = "<extension type=\"file\"><name>files_joomla</name><version>5.2.0</version></extension>\n"
	f.Files["/var/www/shop/app/etc/env.php"] = "<?php\nreturn [\n  'MAGE_MODE' => 'production',\n];\n"
}
