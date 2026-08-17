package p2p

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"
)

// TestDialForProbeOnionWithoutProxyReturnsSpecificError covers p2p/RPC_TOR_SPEC.md section B2
// point 1: a `.onion` address with no SocksProxyAddr configured must return the specific
// onion-requires-proxy error, not a generic timeout/DNS error, and must never attempt a raw TCP
// dial to the (unresolvable) `.onion` hostname.
func TestDialForProbeOnionWithoutProxyReturnsSpecificError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := dialForProbe(ctx, "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:80", ProbeOptions{})
	if err == nil {
		t.Fatalf("expected an error for a .onion address with no SOCKS proxy configured")
	}
	if !strings.Contains(err.Error(), "requires a SOCKS5 proxy") {
		t.Fatalf("expected the onion-requires-proxy error, got: %v", err)
	}
}

// TestDialForProbeOnionWithProxyGoesThroughProxy covers p2p/RPC_TOR_SPEC.md section B2 point 2:
// a `.onion` address WITH a SocksProxyAddr configured must actually attempt to go through that
// proxy address, rather than trying to resolve the `.onion` hostname directly via DNS. This is
// verified by pointing SocksProxyAddr at a real local TCP listener that is NOT a SOCKS5 server:
// the SOCKS5 handshake against it is expected to fail (that failure is the point -- it proves
// the code reached and spoke to the configured proxy address), but it must fail via a SOCKS
// protocol error, not a DNS/hostname-resolution error for the .onion host.
//
// NOTE: this does NOT verify a real end-to-end onion dial through an actual Tor daemon -- no Tor
// daemon is available in this sandbox. That remains an explicitly documented gap; see
// p2p/VERIFICATION.md.
func TestDialForProbeOnionWithProxyGoesThroughProxy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting fake-proxy listener: %v", err)
	}
	defer listener.Close()

	// Accept and immediately close connections so the SOCKS5 client sees a clean failure
	// rather than hanging waiting for a SOCKS5 greeting reply that will never come.
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err = dialForProbe(ctx, "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:80", ProbeOptions{
		SocksProxyAddr: listener.Addr().String(),
	})
	if err == nil {
		t.Fatalf("expected an error dialing through a non-SOCKS5 listener")
	}
	// The failure must come from the proxy handshake itself, not from a DNS/hostname
	// resolution error for the .onion host -- assert it's NOT a DNS-shaped error.
	if strings.Contains(strings.ToLower(err.Error()), "no such host") ||
		strings.Contains(strings.ToLower(err.Error()), "lookup") {
		t.Fatalf("expected a SOCKS5 proxy-handshake error, got what looks like a DNS resolution error: %v", err)
	}
}

// TestDialForProbeNonOnionBypassesConfiguredProxy covers p2p/RPC_TOR_SPEC.md section B2 point 3:
// a non-`.onion` address must always dial directly, even when a (bogus/unreachable)
// SocksProxyAddr is configured -- the proxy is onion-specific only and must not change behavior
// for clearnet addresses.
func TestDialForProbeNonOnionBypassesConfiguredProxy(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting loopback listener: %v", err)
	}
	defer listener.Close()

	acceptedCh := make(chan struct{}, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		acceptedCh <- struct{}{}
		conn.Close()
	}()

	// Reserve, then close, a second port to act as a bogus/unreachable SOCKS proxy address --
	// nothing is listening there.
	bogusListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a bogus proxy port: %v", err)
	}
	bogusProxyAddr := bogusListener.Addr().String()
	bogusListener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := dialForProbe(ctx, listener.Addr().String(), ProbeOptions{SocksProxyAddr: bogusProxyAddr})
	if err != nil {
		t.Fatalf("dialForProbe against a non-.onion address should have dialed directly and succeeded, got: %v", err)
	}
	defer conn.Close()

	select {
	case <-acceptedCh:
		// good: the real listener (not the bogus proxy) accepted the connection.
	case <-time.After(2 * time.Second):
		t.Fatalf("expected the real loopback listener to accept a direct connection")
	}
}

func TestIsOnionAddr(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"example.onion:80", true},
		{"EXAMPLE.ONION:80", true},
		{"127.0.0.1:8080", false},
		{"tari.example.com:18142", false},
		{"not-a-host-port", false},
	}
	for _, c := range cases {
		if got := isOnionAddr(c.addr); got != c.want {
			t.Errorf("isOnionAddr(%q) = %v, want %v", c.addr, got, c.want)
		}
	}
}

// TestProbeWithOptionsZeroValueMatchesProbe checks that ProbeWithOptions with the zero value of
// ProbeOptions behaves identically to Probe against a real in-process responder (reusing the
// pattern from p2p_test.go's TestProbeAgainstInProcessResponder), i.e. Probe's existing exact
// signature/behavior is preserved by becoming a thin wrapper.
func TestProbeWithOptionsZeroValueMatchesProbe(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting loopback listener: %v", err)
	}
	defer listener.Close()

	responderStatic, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating responder static keypair: %v", err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		session, err := ResponderHandshake(ctx, conn, responderStatic)
		if err != nil {
			serverErrCh <- err
			return
		}
		defer session.Close()

		if _, err := session.ExchangeIdentity(ctx); err != nil {
			serverErrCh <- err
			return
		}
		serverErrCh <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info, err := ProbeWithOptions(ctx, listener.Addr().String(), ProbeOptions{})
	if err != nil {
		t.Fatalf("ProbeWithOptions: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("in-process responder side failed: %v", err)
	}
	if !info.Reachable {
		t.Fatalf("expected Reachable=true")
	}
}
