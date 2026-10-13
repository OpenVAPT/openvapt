package scope

import (
	"context"
	"errors"
	"testing"
)

func TestCheckAddr(t *testing.T) {
	allowed := []string{"127.0.0.1:80", "127.10.20.30:443", "[::1]:8080"}
	refused := []string{
		"10.0.0.1:80", "192.168.1.1:443", "8.8.8.8:53", "[2001:db8::1]:80",
		"localhost:80", "example.com:443", "0.0.0.0:80", "garbage",
	}
	for _, a := range allowed {
		if err := CheckAddr(a); err != nil {
			t.Errorf("%s should be allowed: %v", a, err)
		}
	}
	for _, a := range refused {
		if err := CheckAddr(a); !errors.Is(err, ErrNotLocal) {
			t.Errorf("%s must be refused, got %v", a, err)
		}
	}
}

func TestDialerRefusesRemote(t *testing.T) {
	_, err := Dialer{}.DialContext(context.Background(), "tcp", "1.1.1.1:443")
	if !errors.Is(err, ErrNotLocal) {
		t.Fatalf("remote dial must be refused before any packet is sent, got %v", err)
	}
}
