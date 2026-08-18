package p2p

import (
	"context"
	"fmt"
	"net"
	"strings"

	"golang.org/x/net/proxy"
)

// ProbeOptions configures optional behavior for ProbeWithOptions. The zero value preserves the
// exact default, zero-config behavior of Probe (dial directly, no SOCKS proxy).
type ProbeOptions struct {
	// SocksProxyAddr, if non-empty, is the "host:port" address of a SOCKS5 proxy (e.g. a local
	// Tor daemon's SocksPort) used ONLY for dialing `.onion` addresses. It has no effect on
	// non-`.onion` addresses -- matching Tari's own bypass semantics (source:
	// comms/core/src/transports/socks.rs: a bog-standard SOCKS5 proxy dial, onion-specific,
	// no Tari-specific extension).
	SocksProxyAddr string

	// NetworkByte is the single byte written as the very first raw byte of a P2P connection,
	// before Noise starts (source: tari/comms/core/src/protocol/network_info.rs,
	// NodeNetworkInfo.network_wire_byte; real Tari listeners hard-reject a connection whose byte
	// doesn't match their own configured network, source:
	// tari/comms/core/src/connection_manager/listener.rs). The zero value (0x00) is MainNet,
	// matching this package's pre-existing default behavior. See the NetworkByte* constants in
	// p2p/handshake.go for other real Tari networks' values (source:
	// tari/common/src/configuration/network.rs), e.g. NetworkByteEsmeralda = 0x26.
	NetworkByte byte
}

// isOnionAddr reports whether addr's host (as returned by net.SplitHostPort) ends in ".onion"
// (case-insensitive).
func isOnionAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		// Not a "host:port" string at all; can't be a .onion host:port address either.
		return false
	}
	return strings.HasSuffix(strings.ToLower(host), ".onion")
}

// dialForProbe selects and performs the appropriate dial for addr given opts:
//   - `.onion` address + opts.SocksProxyAddr set -> dial through a SOCKS5 proxy at
//     opts.SocksProxyAddr (golang.org/x/net/proxy.SOCKS5), honoring ctx via DialContext (the
//     pulled golang.org/x/net version's SOCKS5 dialer implements proxy.ContextDialer natively).
//   - `.onion` address + no proxy configured -> a clean, specific, actionable error. Never
//     attempts a raw TCP dial to a `.onion` hostname (it cannot resolve).
//   - non-`.onion` address -> always dials directly via net.Dialer.DialContext, regardless of
//     whether a SOCKS proxy is configured (the proxy is onion-specific only; a configured proxy
//     must not change behavior for clearnet addresses).
func dialForProbe(ctx context.Context, addr string, opts ProbeOptions) (net.Conn, error) {
	if !isOnionAddr(addr) {
		dialer := net.Dialer{}
		return dialer.DialContext(ctx, "tcp", addr)
	}

	if opts.SocksProxyAddr == "" {
		return nil, fmt.Errorf("p2p: dialing onion address %q requires a SOCKS5 proxy (see ProbeOptions.SocksProxyAddr); no proxy configured", addr)
	}

	socksDialer, err := proxy.SOCKS5("tcp", opts.SocksProxyAddr, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("p2p: constructing SOCKS5 dialer for proxy %q: %w", opts.SocksProxyAddr, err)
	}

	if contextDialer, ok := socksDialer.(proxy.ContextDialer); ok {
		return contextDialer.DialContext(ctx, "tcp", addr)
	}

	// Fallback for a golang.org/x/net version whose SOCKS5 dialer doesn't implement
	// proxy.ContextDialer: use the context-unaware Dial, but still honor ctx.Done() via a
	// wrapping goroutine/select so callers get cancellation.
	type result struct {
		conn net.Conn
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		conn, err := socksDialer.Dial("tcp", addr)
		resultCh <- result{conn, err}
	}()
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("p2p: dialing %q via SOCKS5 proxy %q: %w", addr, opts.SocksProxyAddr, ctx.Err())
	case res := <-resultCh:
		return res.conn, res.err
	}
}
