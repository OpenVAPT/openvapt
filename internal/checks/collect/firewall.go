package collect

import (
	"context"
	"regexp"
	"strconv"
	"strings"

	"github.com/openvapt/openvapt/internal/sys"
)

// ---------- Host firewall rules ----------

// FWRule is one incoming "allow" rule for a port or port range.
type FWRule struct {
	Engine   string // ufw, nftables or iptables
	Proto    string // tcp, udp or "" for both
	From, To int    // port range, inclusive
	Source   string // "anywhere" or the restricted source
	Raw      string // the rule as printed by the tool (no secrets in firewall rules)
}

// Any reports whether the rule admits every source address.
func (r FWRule) Any() bool { return r.Source == "anywhere" }

// Covers reports whether the rule applies to a protocol and port.
func (r FWRule) Covers(proto string, port int) bool {
	return port >= r.From && port <= r.To && (r.Proto == "" || strings.HasPrefix(proto, r.Proto))
}

// Firewall is the host firewall as read from the first engine that answered.
type Firewall struct {
	Engine      string   // "" when no firewall tool answered
	DefaultDeny bool     // incoming traffic is dropped unless a rule allows it
	Rules       []FWRule // allow rules for incoming traffic
	Docker      []string // iptables DOCKER chain rules that accept published container ports
	DockerUser  bool     // the DOCKER-USER chain drops or rejects something
}

// ReadFirewall runs the read-only status commands of ufw, nftables and
// iptables, in that order, and parses the incoming allow rules of the first
// active one. Docker's iptables chains are read separately, because Docker
// inserts them ahead of ufw and of the INPUT chain.
func ReadFirewall(ctx context.Context, s sys.System) Firewall {
	var fw Firewall
	ipt, iptErr := s.Run(ctx, "iptables", "-S")
	if out, err := s.Run(ctx, "ufw", "status", "verbose"); err == nil && strings.Contains(strings.ToLower(out), "status: active") {
		fw.Engine = "ufw"
		l := strings.ToLower(out)
		fw.DefaultDeny = strings.Contains(l, "deny (incoming)") || strings.Contains(l, "reject (incoming)")
		fw.Rules = parseUFW(out)
	} else if out, err := s.Run(ctx, "nft", "list", "ruleset"); err == nil && strings.Contains(out, "hook input") {
		fw.Engine = "nftables"
		fw.DefaultDeny, fw.Rules = parseNFT(out)
	} else if iptErr == nil && strings.Contains(ipt, "-P INPUT") {
		fw.Engine = "iptables"
		fw.DefaultDeny = strings.Contains(ipt, "-P INPUT DROP") || strings.Contains(ipt, "-P INPUT REJECT")
		fw.Rules = parseIPTables(ipt)
	}
	if iptErr == nil {
		for _, line := range strings.Split(ipt, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "-A DOCKER ") && strings.Contains(line, "-j ACCEPT") && strings.Contains(line, "--dport") {
				fw.Docker = append(fw.Docker, line)
			}
			if strings.HasPrefix(line, "-A DOCKER-USER ") && (strings.Contains(line, "-j DROP") || strings.Contains(line, "-j REJECT")) {
				fw.DockerUser = true
			}
		}
	}
	return fw
}

var multiSpace = regexp.MustCompile(`\s{2,}`)

// parseUFW reads the rule table of "ufw status verbose":
//
//	To                         Action      From
//	22/tcp                     ALLOW IN    Anywhere
//	3306                       ALLOW IN    10.0.0.0/8
func parseUFW(out string) []FWRule {
	var rules []FWRule
	table := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "--") {
			table = true
			continue
		}
		if !table || t == "" {
			continue
		}
		cols := multiSpace.Split(t, -1)
		if len(cols) < 3 {
			continue
		}
		action := strings.ToUpper(cols[1])
		if !strings.HasPrefix(action, "ALLOW") && !strings.HasPrefix(action, "LIMIT") || strings.Contains(action, "OUT") || strings.Contains(action, "FWD") {
			continue
		}
		to := strings.TrimSpace(strings.Replace(cols[0], "(v6)", "", 1))
		if f := strings.Fields(to); len(f) >= 3 && f[1] == "on" { // "80/tcp on eth0": still incoming
			if f[2] == "lo" {
				continue // loopback only, not reachable from the network
			}
			to = f[0]
		}
		proto := ""
		if p, pr, ok := strings.Cut(to, "/"); ok {
			to, proto = p, pr
		}
		if strings.EqualFold(to, "anywhere") {
			to = allPorts // "Anywhere ALLOW IN 10.0.0.5" admits that source on every port
		}
		src := strings.TrimSpace(strings.Replace(cols[2], "(v6)", "", 1))
		if strings.EqualFold(src, "anywhere") {
			src = "anywhere"
		}
		for _, r := range portRanges(to) {
			rules = append(rules, FWRule{Engine: "ufw", Proto: proto, From: r[0], To: r[1], Source: src, Raw: t})
		}
	}
	return rules
}

var nftDport = regexp.MustCompile(`\b(tcp|udp) dport (\{[^}]*\}|\S+)`)
var nftSaddr = regexp.MustCompile(`\bip6? saddr (!=\s*)?(\{[^}]*\}|\S+)`)
var nftAccept = regexp.MustCompile(`\baccept\b`)
var nftLoopback = regexp.MustCompile(`\biif(name)? "?lo"?(\s|$)`)

// nftIface matches an input interface (iif or iifname) that is not negated.
var nftIface = regexp.MustCompile(`\biif(?:name)? (?:==\s*)?("[^"]+"|\{[^}]*\}|[^\s!=]\S*)`)

// parseNFT reads accept rules with a destination port in input-hook chains.
func parseNFT(out string) (bool, []FWRule) {
	var rules []FWRule
	deny := false
	inInput := false
	for _, line := range strings.Split(out, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "chain ") {
			inInput = false
			continue
		}
		if strings.Contains(t, "hook input") {
			inInput = true
			if strings.Contains(t, "policy drop") || strings.Contains(t, "policy reject") {
				deny = true
			}
			continue
		}
		// The verdict may be followed by a comment: tcp dport 22 accept comment "ssh".
		verdict := t
		if i := strings.Index(t, " comment "); i >= 0 {
			verdict = t[:i]
		}
		if !inInput || !nftAccept.MatchString(verdict) || nftLoopback.MatchString(verdict) || strings.Contains(verdict, "dport !=") {
			continue
		}
		m := nftDport.FindStringSubmatch(verdict)
		if m == nil {
			// An accept with no destination port admits every port, unless it
			// only matches return traffic, ICMP or another non-port protocol.
			if nftPortless(verdict) {
				m = []string{"", "", allPorts}
			} else {
				continue
			}
		}
		src := "anywhere"
		if sm := nftSaddr.FindStringSubmatch(verdict); sm != nil && sm[1] == "" {
			src = strings.Trim(sm[2], "{} ") // "saddr != X" admits everyone else, so it stays anywhere
			if strings.HasPrefix(src, "@") {
				src = "set " + src
			}
		}
		// A port-less accept limited to one non-loopback input interface
		// (a VPN or container bridge) admits only that interface's traffic.
		if src == "anywhere" && m[2] == allPorts {
			if im := nftIface.FindStringSubmatch(verdict); im != nil {
				src = "interface " + strings.Trim(im[1], `"{} `)
			}
		}
		for _, r := range portRanges(strings.Trim(m[2], "{} ")) {
			rules = append(rules, FWRule{Engine: "nftables", Proto: m[1], From: r[0], To: r[1], Source: src, Raw: verdict})
		}
	}
	return deny, rules
}

// parseIPTables reads "-A <chain> ... --dport(s) N -j ACCEPT" rules in
// chains that filter incoming traffic (INPUT and the chains ufw creates for
// it). FORWARD, OUTPUT and Docker's chains are not about this host's ports.
func parseIPTables(out string) []FWRule {
	var rules []FWRule
	for _, line := range strings.Split(out, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 || f[0] != "-A" || !strings.Contains(line, "-j ACCEPT") {
			continue
		}
		chain := f[1]
		if chain != "INPUT" && !strings.HasPrefix(chain, "ufw-user-input") && !strings.HasPrefix(chain, "ufw-before-input") {
			continue
		}
		var proto, ports, src, iface, ipset string
		loopback, negPort := false, false
		for i := 0; i+1 < len(f); i++ {
			neg := i > 0 && f[i-1] == "!" // iptables prints negation as "! -s X"
			switch f[i] {
			case "-p":
				proto = f[i+1]
			case "--dport", "--dports":
				ports, negPort = f[i+1], neg
			case "-s":
				if !neg { // "! -s X" admits everyone except X, so it stays anywhere
					src = f[i+1]
				}
			case "-i":
				loopback = f[i+1] == "lo" && !neg
				if !neg {
					iface = f[i+1]
				}
			case "--match-set":
				// "-m set --match-set NAME src" admits only the set's members.
				if !neg && i+2 < len(f) && strings.Contains(f[i+2], "src") {
					ipset = f[i+1]
				}
			}
		}
		if loopback || negPort {
			continue
		}
		if ports == "" {
			// A port-less ACCEPT in INPUT or ufw-user-input admits every port,
			// unless it only matches return traffic or a non-port protocol.
			// ufw-before-input holds ufw's own boilerplate (ICMP, DHCP,
			// mDNS, established traffic), so it is not treated this way.
			if strings.HasPrefix(chain, "ufw-before-input") || !iptPortless(line, proto) {
				continue
			}
			ports = allPorts
			if src == "" && ipset != "" {
				src = "ipset " + ipset
			}
			if src == "" && iface != "" {
				src = "interface " + iface
			}
		}
		switch strings.ToLower(proto) {
		case "all":
			proto = ""
		case "6":
			proto = "tcp"
		case "17":
			proto = "udp"
		}
		if src == "" || src == "0.0.0.0/0" || src == "::/0" {
			src = "anywhere"
		}
		for _, r := range portRanges(ports) {
			rules = append(rules, FWRule{Engine: "iptables", Proto: proto, From: r[0], To: r[1], Source: src, Raw: strings.TrimSpace(line)})
		}
	}
	return rules
}

// allPorts is the port list used for a rule that names no port.
const allPorts = "1:65535"

var nftNonPort = regexp.MustCompile(`\bct state\b|\bct status\b|\bicmp(v6)?\b|\bipv6-icmp\b|\bl4proto\b|\bip6? protocol\b|\bnexthdr\b|\bsport\b|\bigmp\b|\besp\b|\bah\b|\bsctp\b|\bgre\b`)

var nftCtState = regexp.MustCompile(`\bct state (\{[^}]*\}|\S+)`)

// nftPortless reports whether an nftables accept rule without a dport
// matches new connections to every port.
func nftPortless(rule string) bool {
	if m := nftCtState.FindStringSubmatch(rule); m != nil {
		return strings.Contains(m[1], "new") && !nftNonPort.MatchString(strings.Replace(rule, m[0], "", 1))
	}
	return !nftNonPort.MatchString(rule)
}

// iptPortless reports whether an iptables ACCEPT rule without --dport
// matches new TCP or UDP connections to every port.
func iptPortless(line, proto string) bool {
	switch strings.ToLower(proto) {
	case "", "all", "tcp", "udp", "6", "17":
	default:
		return false // icmp, esp, gre and other protocols have no ports
	}
	if strings.Contains(line, "--sport") || strings.Contains(line, "--icmp-type") {
		return false
	}
	f := strings.Fields(line)
	for i := 0; i+1 < len(f); i++ {
		if f[i] == "--state" || f[i] == "--ctstate" {
			if !strings.Contains(strings.ToUpper(f[i+1]), "NEW") {
				return false // only return traffic (ESTABLISHED, RELATED)
			}
		}
	}
	return true
}

// portRanges parses "22", "80,443", "8000:8100" and "8000-8100" lists.
// Named ufw application profiles ("Apache Full") are not ports and yield nothing.
func portRanges(s string) [][2]int {
	var out [][2]int
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }) {
		lo, hi, rng := strings.Cut(p, ":")
		if !rng {
			lo, hi, rng = strings.Cut(p, "-")
		}
		a, err := strconv.Atoi(lo)
		if err != nil || a < 1 || a > 65535 {
			continue
		}
		b := a
		if rng {
			if b, err = strconv.Atoi(hi); err != nil || b < a || b > 65535 {
				continue
			}
		}
		out = append(out, [2]int{a, b})
	}
	return out
}
