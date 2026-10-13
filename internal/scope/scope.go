// Package scope is the security boundary of OpenVAPT.
//
// OpenVAPT may only ever look at the machine it runs on. Every network
// connection the tool makes goes through Dialer, which refuses any address
// that is not a loopback address (127.0.0.0/8 or ::1). There is no flag,
// option or environment variable that turns this off, on purpose.
package scope

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// ErrNotLocal is returned for any attempt to reach another machine.
var ErrNotLocal = errors.New("refused: OpenVAPT only connects to this machine (loopback addresses)")

// IsLoopback reports whether host is a literal loopback IP address.
// Host names are deliberately NOT resolved: "localhost" could be pointed at
// another machine through /etc/hosts or DNS, so only IP literals count.
func IsLoopback(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// CheckAddr validates a "host:port" address before any connection is made.
func CheckAddr(addr string) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrNotLocal, err)
	}
	if !IsLoopback(host) {
		return fmt.Errorf("%w: %q", ErrNotLocal, host)
	}
	return nil
}

// Dialer is a net.Dialer wrapper that enforces CheckAddr on every dial,
// including dials made by the HTTP client after redirects.
type Dialer struct {
	Timeout time.Duration
}

// DialContext connects only if addr is a loopback address. The check runs on
// the address actually being dialled, so redirects to other hosts fail too.
func (d Dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if err := CheckAddr(addr); err != nil {
		return nil, err
	}
	nd := net.Dialer{Timeout: d.Timeout}
	conn, err := nd.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	// Defence in depth: confirm the connected peer really is loopback.
	if ta, ok := conn.RemoteAddr().(*net.TCPAddr); ok && !ta.IP.IsLoopback() {
		_ = conn.Close()
		return nil, ErrNotLocal
	}
	return conn, nil
}
