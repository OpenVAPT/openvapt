package academy

// Modules for the deeper container checks (HOST-CTR-005 and later), the
// application framework and deeper CMS checks (WEB-APP, WEB-CMS-012 and
// later) and the cross-cutting hygiene checks (HOST-SEC, HOST-CRON,
// HOST-SSH-013, HOST-USR-008 to 010). Registered from init so that this
// file never edits the module slices other files build.

var containersApps = []Module{
	{
		ID: "A5", Title: "Container Runtime Hardening Depth", Level: Applied, Minutes: 35,
		Summary: "Beyond \"is the daemon on TCP\": the daemon defaults, socket ownership, confinement profiles, resource limits and image trust that decide what a compromised container can do to its host.",
		Objectives: []string{
			"Read /etc/docker/daemon.json and a container's hostconfig.json and name each setting that limits blast radius.",
			"Explain why the Docker socket and the docker group are root, and what rootless mode changes.",
			"Judge a running container by four questions: who is it, what can it call, how much can it use, and can it change itself.",
		},
		Sections: []Section{
			{"The Daemon Sets the Defaults", []string{
				"Every container inherits what the daemon does not forbid. The daemon's configuration file, /etc/docker/daemon.json, is therefore the first place to look: userns-remap maps container root to an unprivileged host user, no-new-privileges stops setuid escalation, icc false keeps containers from talking to each other on the default bridge, live-restore keeps containers up through a daemon restart (HOST-CTR-002). The deeper checks add the settings that are easy to forget: a log driver with max-size so one container cannot fill the disk (HOST-CTR-005), userland-proxy false so no extra root process sits on each published port (HOST-CTR-006), default-ulimits so file descriptors and processes are bounded for every container (HOST-CTR-007), and no insecure registries, debug or experimental flags (HOST-CTR-010).",
				"NIST SP 800-190 describes the same idea as hardening the host operating system and the container runtime together: the runtime's configuration is part of the host's attack surface, not something the images can fix later.",
			}},
			{"The Socket Is Root", []string{
				"The Docker API has no concept of a limited user: anyone who can send it requests can start a privileged container with the host's root filesystem mounted and is root a moment later. On a Unix socket that means whoever can write /var/run/docker.sock. The daemon creates it as root:docker mode 660, so the question becomes who is in the docker group. OpenVAPT lists the members and treats the group as a list of administrators without sudo, logging or a password prompt (HOST-CTR-008).",
				"Rootless mode moves the daemon itself into a user namespace owned by an ordinary account. A breakout then lands in that account, not in root. It does not suit every workload (some network and storage features differ), so HOST-CTR-009 reports it as information to feed a design decision rather than as a failure.",
			}},
			{"Confinement, Limits and Identity Inside the Container", []string{
				"A container is ordinary processes with namespaces and cgroups around them, and three more layers that are easy to switch off. The default seccomp profile removes around 40 dangerous system calls; AppArmor or SELinux limits what the container's root may touch on the host. SecurityOpt entries such as seccomp=unconfined or apparmor=unconfined remove those layers for that container (HOST-CTR-011). Memory and PID limits (HOST-CTR-012) turn a fork bomb or a leak into one container's problem instead of the host's.",
				"Finally, who runs inside matters. A process that is root in the container is root for every kernel bug, and a writable root filesystem lets an intruder install tools and persist. USER in the image and --read-only with a tmpfs for scratch space close both (HOST-CTR-013). The same questions apply to containerd and Podman: a containerd gRPC endpoint on TCP without TLS is the Docker API problem again, and Podman's containers.conf sets the confinement defaults every container inherits (HOST-CTR-014).",
			}},
			{"Trusting What You Pull", []string{
				"docker pull takes whatever the registry returns for a tag. Docker Content Trust (DOCKER_CONTENT_TRUST=1) makes the client verify a signature first, so a substituted image fails to pull instead of running as root on your host (HOST-CTR-015). Pair it with pinning images by digest in production and scanning images before they are pushed.",
			}},
			{"In Summary", []string{
				"The Docker daemon sets the defaults every container inherits, and the socket is root. Bound logs, keep the userland proxy and ulimits deliberate, restrict the socket and the docker group, keep seccomp and AppArmor on, set memory and PID limits, avoid root with a writable root filesystem, never expose a daemon over TCP without TLS, and verify what you pull.",
			}},
		},
		KeyTerms:      []string{"Container", "Namespace", "Seccomp Profile", "Rootless Mode", "Content Trust", "Least Privilege"},
		RelatedChecks: []string{"HOST-CTR-005", "HOST-CTR-006", "HOST-CTR-007", "HOST-CTR-008", "HOST-CTR-009", "HOST-CTR-010", "HOST-CTR-011", "HOST-CTR-012", "HOST-CTR-013", "HOST-CTR-014", "HOST-CTR-015"},
		Lab: []string{
			"Run: openvapt demo --only HOST-CTR- --out a5 and sort the findings into daemon defaults, socket and group, per-container settings and image trust.",
			"Compare the vulnerable and hardened daemon.json and hostconfig.json in internal/lab/fixtures_containers_apps.go line by line; for each difference, name the check that would notice it.",
			"On a test machine you are allowed to assess: getent group docker, then stat -c '%a %U:%G %n' /var/run/docker.sock, and decide whether the group's members should instead use sudo docker.",
		},
		Quiz: []Question{
			{"A user is in the docker group but has no sudo rights. What can they do?", []string{"Only list containers", "Anything root can do, by starting a container with the host filesystem mounted", "Nothing until an administrator approves"}, 1, "The Docker API is equivalent to root; group membership is unaudited root access."},
			{"Which setting removes Docker's default system call filter for one container?", []string{"--memory 512m", "--security-opt seccomp=unconfined", "--read-only"}, 1, "seccomp=unconfined disables the default profile that blocks dangerous system calls."},
			{"Why is a json-file log driver without max-size a problem?", []string{"Logs are encrypted and cannot be read", "One container can fill the host's disk with its own logs", "Docker refuses to start"}, 1, "Unbounded logs are a denial of service against the host and every neighbour."},
			{"What does rootless mode change?", []string{"Containers can no longer use the network", "The daemon and containers run inside a user namespace as an ordinary account, so a breakout does not land in root", "Images are signed automatically"}, 1, "Rootless mode limits the blast radius of a breakout; it does not sign images or remove networking."},
		},
		Refs: []Ref{{"NIST SP 800-190, Application Container Security Guide", "https://csrc.nist.gov/pubs/sp/800/190/final"}, {"Docker documentation, Docker Engine security", "https://docs.docker.com/engine/security/"}, {"Docker documentation, Rootless mode", "https://docs.docker.com/engine/security/rootless/"}, {"OWASP Docker Security Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Docker_Security_Cheat_Sheet.html"}, {"CIS Docker Benchmark (recommendation numbers are cited in each check)", "https://www.cisecurity.org/benchmark/docker"}},
	},
	{
		ID: "A6", Title: "Application Framework and CMS Configuration", Level: Applied, Minutes: 35,
		Summary: "How Laravel, Symfony, Rails, Spring Boot, Flask, Drupal, Joomla, Magento, Ghost and WordPress each express the same five production mistakes, and how to find them from the files on disk.",
		Objectives: []string{
			"Map a framework's configuration file and setting names to the five mistakes: debug on, secret exposed, wrong environment, lifecycle expired, writable code.",
			"Find application projects on a server from their configuration files without running them.",
			"Explain why on-disk checks and HTTP checks of the same weakness complement each other.",
		},
		Sections: []Section{
			{"Five Mistakes, Many Spellings", []string{
				"Frameworks differ in syntax and agree on failure modes. Debug mode is APP_DEBUG=true in Laravel (WEB-APP-001), APP_ENV=dev in Symfony (WEB-APP-003), DEBUG = True in Django (WEB-PY-001), debug=True in a Flask entry file (WEB-APP-007), MAGE_MODE developer in Magento (WEB-CMS-015) and WP_DEBUG in WordPress (WEB-CMS-006). In every case the error page prints configuration, queries or source to whoever triggers an error.",
				"Secrets live in .env files, Rails master.key and secrets.yml, Django settings.py and Spring application.properties. The questions are the same: is the file readable by every local account (WEB-APP-002, WEB-APP-004), is it inside a web root (WEB-DOC-001, WEB-APP-004), and is a generated or empty key still in place (WEB-APP-001, WEB-PY-003). Spring Boot adds its own leak: management.endpoints.web.exposure.include=* publishes env, configprops and heapdump over HTTP (WEB-APP-006).",
			}},
			{"Environment and Transport", []string{
				"Production settings are a mode, not a default. Rails only marks cookies Secure and redirects to HTTPS when config.force_ssl is true (WEB-APP-005); Ghost builds every admin and member link from its configured url, so http:// there means credentials in the clear (WEB-CMS-016); Drupal trusts any Host header until trusted_host_patterns is set (WEB-CMS-013), and update_free_access lets anyone run update.php (WEB-CMS-019).",
			}},
			{"Lifecycle and Writable Code", []string{
				"A CMS past end of life gets no security advisories: Drupal 7, 8 and 9 (WEB-CMS-012) and Joomla 3 and 4 (WEB-CMS-014) are read from version files on disk. The same reasoning applies to dependencies: a composer.lock or package-lock.json untouched for a year means every library fix since then is missing (WEB-APP-008, informational).",
				"Code the web server can be made to run must not be writable by other users. chmod -R 777 storage makes Laravel's bootstrap/cache and Symfony's var/cache, which hold compiled PHP, writable by every account (WEB-APP-010). A .git folder inside the document root (WEB-APP-009) is one server rule away from publishing the source; WEB-EXP-001 tests whether that has already happened. WordPress adds two small exposures: wp-cron.php reachable by visitors (WEB-CMS-017) and the /?author=1 redirect that reveals login names (WEB-CMS-018).",
			}},
			{"Finding Projects Without Running Them", []string{
				"OpenVAPT looks for projects where administrators put them: /srv, /opt, /var/www, home folders and every configured web root, three folders deep, and recognises a framework by a marker setting (APP_KEY for Laravel, APP_SECRET for Symfony, config/master.key for Rails). Files under those folders are read without following symbolic links, because a site user could point .env at /etc/shadow. Only the path and the setting name reach the report; a value is never copied, and the report is redacted again before it is written.",
			}},
			{"In Summary", []string{
				"Frameworks fail the same five ways under different names: debug on, a default or readable secret, development environment in production, transport not forced and writable code or stale dependencies. Find projects from files, read .env without following links, and check each setting in its own spelling.",
			}},
		},
		KeyTerms:      []string{"Debug Mode", "Environment File", "Trusted Host", "Lock File", "End of Life", "Hardening"},
		RelatedChecks: []string{"WEB-APP-", "WEB-CMS-012", "WEB-CMS-013", "WEB-CMS-014", "WEB-CMS-015", "WEB-CMS-016", "WEB-CMS-017", "WEB-CMS-018", "WEB-CMS-019"},
		Lab: []string{
			"Run: openvapt demo --only WEB-APP-,WEB-CMS- --out a6 and group the findings under the five mistakes.",
			"Read the vulnerable and hardened Laravel, Symfony, Rails and Spring Boot files in internal/lab/fixtures_containers_apps.go and write the one-line fix for each.",
			"Pick one framework you use and list its equivalent of each of the five mistakes, with the exact setting name; propose it as a new check (module A4).",
		},
		Quiz: []Question{
			{"Which Spring Boot setting publishes environment variables over HTTP?", []string{"server.port=8080", "management.endpoints.web.exposure.include=*", "spring.profiles.active=prod"}, 1, "exposure.include=* exposes env, configprops and heapdump unless security is added."},
			{"Why does OpenVAPT read .env files without following symbolic links?", []string{"Symbolic links are slower to read", "A site user could replace .env with a link to a root-only file such as /etc/shadow", "Frameworks forbid links"}, 1, "Files under user-writable folders are untrusted; refusing links stops a confused-deputy read."},
			{"A composer.lock is 800 days old. What does that prove?", []string{"The application is vulnerable to a specific CVE", "No dependency updates have been applied in that time, so every library fix since then is missing", "Composer is not installed"}, 1, "It is a freshness signal; the known-vulnerability checks and composer audit name specific issues."},
			{"What does Rails config.force_ssl = true do beyond redirecting to HTTPS?", []string{"Nothing else", "Marks cookies Secure and sends Strict-Transport-Security", "Disables the asset pipeline"}, 1, "force_ssl also protects the session cookie and enables HSTS."},
		},
		Refs: []Ref{{"Laravel documentation, Deployment", "https://laravel.com/docs/12.x/deployment"}, {"Symfony documentation, How to Deploy a Symfony Application", "https://symfony.com/doc/current/deployment.html"}, {"Ruby on Rails Guides, Securing Rails Applications", "https://guides.rubyonrails.org/security.html"}, {"Spring Boot documentation, Actuator endpoints", "https://docs.spring.io/spring-boot/reference/actuator/endpoints.html"}, {"Drupal.org, Trusted Host settings", "https://www.drupal.org/docs/getting-started/installing-drupal/trusted-host-settings"}, {"OWASP ASVS 4.0.3, V14 Configuration", "https://github.com/OWASP/ASVS/blob/v4.0.3/4.0/en/0x22-V14-Config.md"}, {"OWASP WSTG-CONF-02, Test Application Platform Configuration", "https://wstg.owasp.org/v4.2/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/02-Test_Application_Platform_Configuration/"}},
	},
	{
		ID: "P20", Title: "Secrets, Cron and Account Hygiene", Level: Practitioner, Minutes: 20,
		Summary: "The small cross-cutting habits that stop a low-privilege foothold becoming root: no secrets in readable files, restricted SSH keys, cron that runs only root-owned code, a clean PATH and consistent account files.",
		Objectives: []string{
			"Find secrets that any local user can read and explain why that is a lateral movement path.",
			"Trace what a root cron job really executes and who could change it.",
			"Spot account-file inconsistencies that tools such as pwck report.",
		},
		Sections: []Section{
			{"Secret Sprawl", []string{
				"Secrets drift into configuration files, backups and .env files, and the file mode decides who else can use them. A password in a world-readable file under /etc or a web root is available to every website, service account and compromised process on the machine. OpenVAPT reads world-readable configuration-like files, within a fixed budget, for private key headers, cloud access key ids and password or token assignments, and reports only the file and the kind of match (HOST-SEC-001). The fix is two-fold: restrict the mode, and rotate the secret, because readable means leaked.",
			}},
			{"Keys and Options", []string{
				"A key in root's authorized_keys is a root password without an expiry date. OpenSSH lets each key carry options: from= limits the source addresses, command= pins the key to one program, and restrict turns off forwarding and PTYs. A root key with none of them, or an authorized_keys file others can write, is a quiet standing risk (HOST-SSH-013).",
			}},
			{"What Root Runs on Schedule", []string{
				"HOST-FS-005 protects the cron tables; the next question is what they run. A root job that executes /usr/local/bin/backup.sh is only as trustworthy as that file and its folder: if any user can edit or replace it, their code runs as root at the next minute (HOST-CRON-001). Jobs that call a bare command name depend on PATH, so a world-writable folder or a relative entry in cron's PATH lets anyone plant a program that root runs (HOST-CRON-002, MITRE ATT&CK T1574.007).",
			}},
			{"Consistent Account Files", []string{
				"/etc/passwd, /etc/shadow and /etc/group are three files that must agree. Two groups sharing a GID are one group to the kernel (HOST-USR-008). An account in passwd with no shadow line, a hash left in passwd, or a shadow line for a deleted user are signs of hand edits or an interrupted removal (HOST-USR-009); pwck and grpck report the same. Home directories complete the picture: with others allowed in, any account can read another user's shell history and SSH keys or plant a .bashrc (HOST-USR-010).",
			}},
			{"In Summary", []string{
				"Secrets leak through readable files, keys without options, cron jobs that run writable programs and account files that disagree. Walk the configuration tree with bounds, restrict authorized_keys with from= and command=, keep cron programs and PATH root-owned, and reconcile passwd, shadow and group.",
			}},
		},
		KeyTerms:      []string{"Secret Sprawl", "Authorized Keys Options", "PATH Interception", "Shadow File", "Privilege Escalation"},
		RelatedChecks: []string{"HOST-SEC-", "HOST-CRON-", "HOST-SSH-013", "HOST-USR-008", "HOST-USR-009", "HOST-USR-010"},
		Lab: []string{
			"Run: openvapt demo --only HOST-SEC-,HOST-CRON-,HOST-SSH-013,HOST-USR-008,HOST-USR-009,HOST-USR-010 --out p15 and, for each finding, write who gains what.",
			"In internal/lab/fixtures_containers_apps.go, follow the vulnerable /etc/crontab from PATH to the backup script and list every file a non-root user could change to run code as root.",
			"On a test machine you are allowed to assess: pwck -r ; grpck -r ; find /etc -type f -perm -0004 -name '*.conf' | head  and compare with the report.",
		},
		Quiz: []Question{
			{"A root cron job runs backup-db with no path. Where is the risk?", []string{"Cron refuses to run it", "Whichever folder on cron's PATH is writable by others can supply a fake backup-db", "Only in /etc/crontab's permissions"}, 1, "PATH interception: the first matching file on PATH runs as root."},
			{"What does from=\"203.0.113.0/24\" in authorized_keys do?", []string{"Sets the key's expiry date", "Limits the addresses the key may log in from", "Encrypts the key"}, 1, "from= restricts source addresses; command= and restrict limit what the key can do."},
			{"An account appears in /etc/passwd with x but has no /etc/shadow line. Why does it matter?", []string{"It cannot own files", "Its password state is undefined and differs between tools; the files were edited inconsistently", "It is automatically root"}, 1, "pwck reports this; pwconv or vipw repairs it."},
		},
		Refs: []Ref{{"OWASP Secrets Management Cheat Sheet", "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"}, {"sshd(8), AUTHORIZED_KEYS FILE FORMAT", "https://man.openbsd.org/sshd.8#AUTHORIZED_KEYS_FILE_FORMAT"}, {"MITRE ATT&CK T1574.007, Path Interception by PATH Environment Variable", "https://attack.mitre.org/techniques/T1574/007/"}, {"MITRE ATT&CK T1053.003, Cron", "https://attack.mitre.org/techniques/T1053/003/"}, {"pwck(8), Linux man-pages", "https://man7.org/linux/man-pages/man8/pwck.8.html"}, {"NIST SP 800-53 Rev. 5, IA-5 Authenticator Management", "https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final"}},
	},
}

var containersAppsTerms = map[string]string{
	"Seccomp Profile":         "A list of system calls a process may make; a container runtime applies a default profile that blocks dangerous calls, and unconfined removes it.",
	"Rootless Mode":           "Running the container daemon and its containers inside a user namespace as an ordinary account, so a breakout does not land in root.",
	"Content Trust":           "Verifying a signature on an image before pulling or running it, so a substituted image is refused.",
	"Environment File":        "A .env or similar file of KEY=value settings that an application reads at start, usually holding secrets and the debug and environment switches.",
	"Trusted Host":            "A setting that lists the host names an application accepts in the Host header, so attackers cannot make it build links to their own domain.",
	"Lock File":               "A file such as composer.lock or package-lock.json that pins the exact versions of every dependency an application installs.",
	"Secret Sprawl":           "Secrets copied into configuration files, backups, scripts and environment files where more people and processes can read them than intended.",
	"Authorized Keys Options": "Prefixes in an SSH authorized_keys line, such as from=, command= and restrict, that limit where a key may log in from and what it may do.",
	"PATH Interception":       "Planting a program in a folder that appears early in PATH, or in a writable PATH folder, so a privileged job runs it instead of the intended command.",
	"Shadow File":             "/etc/shadow, the root-only file that holds password hashes and ageing data for the accounts listed in /etc/passwd.",
}

func init() {
	Modules = append(Modules, containersApps...)
	for k, v := range containersAppsTerms {
		Glossary[k] = v
	}
	// Place the new modules in the semester course so every module is taught.
	if c := CourseByID("semester-14"); c != nil {
		for i := range c.Sessions {
			switch c.Sessions[i].Week {
			case 10:
				c.Sessions[i].Modules = append(c.Sessions[i].Modules, "A5")
			case 11:
				c.Sessions[i].Modules = append(c.Sessions[i].Modules, "A6", "P20")
			}
		}
	}
}
