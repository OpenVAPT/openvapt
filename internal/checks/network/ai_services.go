package network

import (
	"context"
	"regexp"
	"strings"

	"github.com/openvapt/openvapt/internal/check"
	"github.com/openvapt/openvapt/internal/sys"
)

// NET-AI: self-hosted AI services. Detection only: listening sockets are read
// from /proc/net and configuration files are read from disk. No request,
// prompt or model call is ever sent to any AI service.

// aiPorts are the documented default ports of self-hosted AI model servers,
// AI web interfaces, AI cluster dashboards and vector databases. Most of them
// ship with no authentication and are designed to listen on loopback only.
var aiPorts = map[int]string{
	11434: "Ollama model API",
	1234:  "LM Studio local server",
	7860:  "Gradio AI web interface",
	8188:  "ComfyUI image generation interface",
	8265:  "Ray dashboard and jobs API",
	6333:  "Qdrant vector database",
	19530: "Milvus vector database",
	6006:  "TensorBoard",
}

var jupyterPaths = []string{
	"/etc/jupyter/jupyter_server_config.py", "/etc/jupyter/jupyter_notebook_config.py",
	"/usr/local/etc/jupyter/jupyter_server_config.py", "/usr/local/etc/jupyter/jupyter_notebook_config.py",
	"/root/.jupyter/jupyter_server_config.py", "/root/.jupyter/jupyter_notebook_config.py",
	"/home/*/.jupyter/jupyter_server_config.py", "/home/*/.jupyter/jupyter_notebook_config.py",
}

// jupyterSetting matches one assignment such as c.ServerApp.token = ”.
var jupyterSetting = regexp.MustCompile(`^\s*c\.(ServerApp|NotebookApp|IdentityProvider|PasswordIdentityProvider)\.(token|password|hashed_password|disable_check_xsrf)\s*=\s*(.+?)\s*$`)

// jupyterAuthOff reads Jupyter configuration text and reports, without
// copying any value, whether the token is blanked with no password set, or
// whether cross-site request forgery protection is turned off.
func jupyterAuthOff(text string) []string {
	emptyToken, password, xsrfOff := false, false, false
	for _, line := range strings.Split(text, "\n") {
		m := jupyterSetting.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		v := strings.TrimSpace(strings.SplitN(m[3], "#", 2)[0])
		blank := v == "''" || v == `""` || v == "u''"
		switch m[2] {
		case "token":
			emptyToken = blank
		case "password", "hashed_password":
			password = !blank
		case "disable_check_xsrf":
			xsrfOff = v == "True"
		}
	}
	var out []string
	if emptyToken && !password {
		out = append(out, "token is an empty string and no login password is set, so anyone who reaches the server can run code")
	}
	if xsrfOff {
		out = append(out, "disable_check_xsrf = True: other websites can send requests to the server through a visitor's browser")
	}
	return out
}

func init() {
	check.Register(&check.Check{
		ID: "NET-AI-001", Title: "AI Model Server or Dashboard Reachable From the Network", Domain: check.DomainNetwork,
		Severity: check.High, Category: check.CatNetwork, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L",
		Summary:   "Checks whether a self-hosted AI model server, AI web interface, AI cluster dashboard or vector database listens on a network-reachable address.",
		Rationale: "Many self-hosted AI tools have no login enabled by default. Reached from the network, anyone can use the models and the computing power, read stored documents and embeddings, pull or delete models, and on some dashboards submit jobs that run code.",
		Detection: "Matches network-reachable listening TCP sockets from /proc/net against the documented default ports of Ollama, LM Studio, Gradio, ComfyUI, the Ray dashboard, Qdrant, Milvus and TensorBoard, and records how each is bound. No request, prompt or model call is sent.",
		Fix:       "Bind each service to 127.0.0.1 (Ollama: OLLAMA_HOST=127.0.0.1:11434 in its service environment; Ray: --dashboard-host=127.0.0.1; Gradio: server_name=\"127.0.0.1\"), and if others need it, publish it only through a reverse proxy with authentication and TLS.",
		Verify:    "ss -tlnp  shows these ports on 127.0.0.1 or ::1 only.",
		Refs: []check.Ref{{Title: "Ollama FAQ, How do I configure Ollama server?", URL: "https://github.com/ollama/ollama/blob/main/docs/faq.md"},
			{Title: "Ray documentation, Security", URL: "https://docs.ray.io/en/latest/ray-security/index.html"},
			{Title: "OWASP Top 10 for Large Language Model Applications", URL: "https://genai.owasp.org/llm-top-10/"}},
		Standards: check.Standards{CWE: []string{"CWE-306", "CWE-1327"}, OWASP: []string{"A05:2021", "A07:2021"}, NIST: []string{"SC-7", "CM-7", "AC-3"}, CISTopic: "Expose applications only through a hardened front end"},
		Run:       appPortRun(aiPorts, "AI services are network-reachable", "No AI model server, dashboard or vector database port is network-reachable"),
	})

	check.Register(&check.Check{
		ID: "NET-AI-002", Title: "Jupyter Configuration Weakens Authentication", Domain: check.DomainNetwork,
		Severity: check.High, Category: check.CatIdentity, Effort: check.EffortLow,
		CVSS:      "CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
		Summary:   "Checks whether a Jupyter configuration blanks the login token without setting a password, or turns off cross-site request protection.",
		Rationale: "Jupyter runs any code typed into it with the rights of the account that started it. With the token blanked and no password, anyone who can reach the port, or any local user, gets that account. With XSRF checks off, a web page a user visits can send it commands.",
		Detection: "Reads Jupyter configuration files under /etc/jupyter, /usr/local/etc/jupyter, /root/.jupyter and /home/*/.jupyter and looks for token, password and disable_check_xsrf assignments. Only whether a value is empty is recorded; no token or password is copied.",
		Fix:       "Remove the empty token line so Jupyter generates a random token, or set a password with  jupyter server password . Remove disable_check_xsrf = True. Bind to 127.0.0.1 and reach it through an SSH tunnel.",
		Verify:    "grep -nE 'token|password|disable_check_xsrf' <config file>  shows no empty token and no disabled XSRF check, and the server log prints a URL with a token at start-up.",
		Refs:      []check.Ref{{Title: "Jupyter Server documentation, Security in the Jupyter Server", URL: "https://jupyter-server.readthedocs.io/en/latest/operators/security.html"}},
		Standards: check.Standards{CWE: []string{"CWE-306", "CWE-352"}, OWASP: []string{"A07:2021", "A05:2021"}, NIST: []string{"IA-2", "AC-3"}, CISTopic: "Require authentication for administrative and code execution interfaces"},
		Run: func(ctx context.Context, s sys.System) []check.Result {
			var paths []string
			for _, p := range jupyterPaths {
				if strings.Contains(p, "*") {
					m, _ := s.Glob(p)
					paths = append(paths, m...)
				} else {
					paths = append(paths, p)
				}
			}
			var res []check.Result
			for _, p := range paths {
				r, err := s.ReadFile(ctx, p)
				if err != nil {
					continue
				}
				if ev := jupyterAuthOff(string(r.Data)); len(ev) > 0 {
					res = append(res, check.FailR(p, "Jupyter configuration weakens authentication or request forgery protection", ev...))
				} else if !r.Complete {
					res = append(res, check.IncompleteR(p, "Configuration input was truncated"))
				} else {
					res = append(res, check.PassR(p, "Jupyter keeps token or password authentication and XSRF protection"))
				}
			}
			if len(res) == 0 {
				return []check.Result{check.SkipR("jupyter configuration", "No Jupyter configuration file was found")}
			}
			return res
		},
	})
}
