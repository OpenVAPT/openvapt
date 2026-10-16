package lab

import "github.com/openvapt/openvapt/internal/sys"

// Fixtures for the self-hosted AI service checks (NET-AI-001, NET-AI-002) and
// Apache slow request protection (WEB-APA-011). The file name sorts last
// so it extends, not replaces, the socket tables of earlier fixtures.

func init() { Register(aiVulnerable, aiHardened) }

func aiVulnerable(f *sys.Fake) {
	// Ollama on every IPv6 and IPv4 address (::, port 11434), added to the
	// sockets other fixtures created (this file sorts last so it runs last).
	appendFile(f, "/proc/net/tcp6", "   9: 00000000000000000000000000000000:2CAA 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 10009\n")
	f.Files["/etc/jupyter/jupyter_server_config.py"] = "c.ServerApp.ip = '0.0.0.0'\nc.ServerApp.token = ''\nc.ServerApp.disable_check_xsrf = True\n"
	// Apache with mod_reqtimeout removed: nothing to add.
}

func aiHardened(f *sys.Fake) {
	f.Files["/etc/jupyter/jupyter_server_config.py"] = "c.ServerApp.ip = '127.0.0.1'\n# token is generated at start-up\n"
	f.Files["/etc/apache2/mods-enabled/reqtimeout.load"] = "LoadModule reqtimeout_module /usr/lib/apache2/modules/mod_reqtimeout.so\n"
	appendFile(f, "/etc/apache2/mods-enabled/reqtimeout.conf", "RequestReadTimeout header=20-40,MinRate=500 body=20,MinRate=500\n")
}
