package lab

import (
	"net/http"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

// Fixtures for the systemd, firewall correlation, application server
// (Tomcat, Node.js, Python) and deeper CMS checks. The vulnerable shop runs
// a Node.js API, a Django admin, a Flask report service and Tomcat the
// careless way; the hardened shop runs the same stack behind the proxy.

// addSockets appends listening sockets to a /proc/net table already in f.
func addSockets(f *sys.Fake, table string, socks ...[2]string) {
	lines := strings.SplitN(procTCP(socks...), "\n", 2)
	f.Files[table] += lines[1]
}

func init() {
	Register(stacksVulnerable, stacksHardened)
}

func stacksVulnerable(f *sys.Fake) {
	// systemd: root, no sandbox, writable unit, secrets in Environment=,
	// inspector on 0.0.0.0, a program in /tmp and two Python dev servers.
	file(f, "/etc/systemd/system/shop-api.service", "[Unit]\nDescription=Shop API\n\n[Service]\n"+
		"ExecStart=/usr/bin/node --inspect=0.0.0.0:9229 /srv/shop/server.js\n"+
		"Environment=NODE_ENV=development\nEnvironment=\"DB_PASSWORD=hunter2\" STRIPE_API_KEY=sk_test_redactme\nRestart=always\n", 0o666)
	file(f, "/etc/systemd/system/shop-worker.service", "[Service]\nExecStart=/tmp/shop-worker --queue orders\n", 0o644)
	file(f, "/etc/systemd/system/shop-admin.service", "[Service]\nExecStart=/usr/bin/python3 /srv/shopadmin/manage.py runserver 0.0.0.0:8000\n", 0o644)
	file(f, "/etc/systemd/system/shop-reports.service", "[Service]\nEnvironment=FLASK_DEBUG=1\nExecStart=/usr/local/bin/flask run --host 0.0.0.0\n", 0o644)
	f.Commands["node --version"] = "v18.19.1\n"

	// Django settings straight from startproject.
	f.Files["/srv/shopadmin/shopadmin/settings.py"] = "SECRET_KEY = 'django-insecure-0123456789abcdef'\nDEBUG = True\nALLOWED_HOSTS = ['*']\n" +
		"INSTALLED_APPS = ['django.contrib.admin']\nROOT_URLCONF = 'shopadmin.urls'\n"

	// Tomcat 9 from the Ubuntu packages, with the admin and example apps.
	f.Files["/etc/tomcat9/server.xml"] = `<?xml version="1.0"?>
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="8080" protocol="HTTP/1.1" />
    <Connector port="8009" protocol="AJP/1.3" secretRequired="false" />
  </Service>
</Server>
`
	f.Files["/etc/tomcat9/tomcat-users.xml"] = `<tomcat-users>
  <user username="tomcat" password="s3cret" roles="manager-gui,admin-gui"/>
</tomcat-users>
`
	f.Files["/usr/share/tomcat9-admin/manager/META-INF/context.xml"] = `<Context antiResourceLocking="false" privileged="true">
  <!-- <Valve className="org.apache.catalina.valves.RemoteAddrValve" allow="127\.\d+\.\d+\.\d+|::1" /> -->
</Context>
`
	f.Files["/var/lib/tomcat9/webapps/examples/WEB-INF/web.xml"] = "<web-app/>\n"

	// Application ports on 0.0.0.0: Node.js 3000, Tomcat AJP 8009, inspector 9229.
	addSockets(f, "/proc/net/tcp", [2]string{"00000000", "0BB8"}, [2]string{"00000000", "1F49"}, [2]string{"00000000", "240D"})

	// iptables: MySQL opened to the world, a stale rule for 8443, and a
	// Docker-published port with an empty DOCKER-USER chain.
	f.Commands["iptables -S"] += "-N DOCKER\n-N DOCKER-USER\n" +
		"-A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT\n-A INPUT -p tcp -m tcp --dport 8443 -j ACCEPT\n" +
		"-A DOCKER -d 172.17.0.2/32 ! -i docker0 -o docker0 -p tcp -m tcp --dport 80 -j ACCEPT\n-A DOCKER-USER -j RETURN\n"

	// One web root holding WordPress, Joomla and Drupal configuration.
	file(f, "/var/www/shop/wp-config.php", "<?php\ndefine('DB_NAME', 'shop');\ndefine('DB_PASSWORD', 'hunter2');\n"+
		"define('WP_DEBUG', true);\ndefine('AUTOMATIC_UPDATER_DISABLED', true);\n", 0o666)
	file(f, "/var/www/shop/configuration.php", "<?php\nclass JConfig {\n\tpublic $debug = '1';\n\tpublic $error_reporting = 'maximum';\n\tpublic $password = 'hunter2';\n}\n", 0o644)
	file(f, "/var/www/shop/sites/default/settings.php", "<?php\n$databases['default']['default'] = ['password' => 'hunter2'];\n", 0o664)
	f.HTTPResp["https://"+site+"/administrator/manifests/files/joomla.xml"] = sys.HTTPResponse{Status: 200, Header: http.Header{"Content-Type": {"text/xml"}},
		Body: "<extension type=\"file\"><name>files_joomla</name><author>Joomla! Project</author><version>3.9.0</version></extension>"}
	f.HTTPResp["https://"+site+"/core/CHANGELOG.txt"] = sys.HTTPResponse{Status: 200, Header: http.Header{"Content-Type": {"text/plain"}},
		Body: "Drupal 8.5.0, 2018-03-07\n-----------------------\n"}
}

func stacksHardened(f *sys.Fake) {
	sandbox := "NoNewPrivileges=yes\nProtectSystem=strict\nPrivateTmp=yes\nProtectHome=yes\n"
	file(f, "/etc/systemd/system/shop-api.service", "[Unit]\nDescription=Shop API\n\n[Service]\nUser=shop\nGroup=shop\n"+
		"ExecStart=/usr/bin/node /srv/shop/server.js\nEnvironment=NODE_ENV=production\nEnvironmentFile=/etc/shop/shop.env\n"+
		"ReadWritePaths=/var/lib/shop\n"+sandbox, 0o644)
	file(f, "/etc/systemd/system/shop-admin.service", "[Service]\nDynamicUser=yes\n"+
		"ExecStart=/srv/shopadmin/venv/bin/gunicorn --bind 127.0.0.1:8000 shopadmin.wsgi\n"+sandbox, 0o644)
	file(f, "/etc/systemd/system/shop-admin.service.d/override.conf", "[Service]\nEnvironment=DJANGO_SETTINGS_MODULE=shopadmin.settings\n", 0o644)
	file(f, "/lib/systemd/system/nginx.service", "[Service]\nType=forking\nExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'\n", 0o644)
	f.Infos["/usr/sbin/nginx"] = sys.FileInfo{Path: "/usr/sbin/nginx", Mode: 0o755}
	f.Commands["node --version"] = "v24.11.0\n"

	f.Files["/srv/shopadmin/shopadmin/settings.py"] = "import os\nSECRET_KEY = os.environ['DJANGO_SECRET_KEY']\nDEBUG = os.environ.get('DJANGO_DEBUG') == '1'\n" +
		"ALLOWED_HOSTS = ['" + site + "']\nINSTALLED_APPS = ['django.contrib.admin']\nROOT_URLCONF = 'shopadmin.urls'\n"

	f.Files["/etc/tomcat9/server.xml"] = `<?xml version="1.0"?>
<Server port="-1" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="8080" address="127.0.0.1" protocol="HTTP/1.1" />
    <!-- <Connector port="8009" protocol="AJP/1.3" secretRequired="false" /> -->
  </Service>
</Server>
`
	f.Files["/etc/tomcat9/tomcat-users.xml"] = "<tomcat-users>\n  <!-- <user username=\"tomcat\" password=\"tomcat\" roles=\"manager-gui\"/> -->\n</tomcat-users>\n"

	// Node.js and Tomcat listen on loopback only, behind Apache.
	addSockets(f, "/proc/net/tcp", [2]string{"0100007F", "0BB8"}, [2]string{"0100007F", "1F90"})

	// ufw with one rule per public service.
	f.Commands["ufw status verbose"] = "Status: active\nLogging: on (low)\nDefault: deny (incoming), allow (outgoing), disabled (routed)\nNew profiles: skip\n\n" +
		"To                         Action      From\n--                         ------      ----\n" +
		"22/tcp                     LIMIT IN    Anywhere\n80/tcp                     ALLOW IN    Anywhere\n443/tcp                    ALLOW IN    Anywhere\n"

	file(f, "/var/www/shop/wp-config.php", "<?php\ndefine('DB_NAME', 'shop');\ndefine('DB_PASSWORD', 'hunter2');\n"+
		"define('WP_DEBUG', false);\ndefine('DISALLOW_FILE_EDIT', true);\ndefine('WP_AUTO_UPDATE_CORE', 'minor');\n", 0o640)
}
