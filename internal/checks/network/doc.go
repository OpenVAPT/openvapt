// Package network contains checks about what this machine exposes on the
// network: listening services, the host firewall and TLS on local ports.
// All information is read from inside the machine (/proc/net, firewall
// tools, loopback TLS handshakes). Nothing is sent to other hosts.
package network
