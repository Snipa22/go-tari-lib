// Package p2p implements a minimal Tari `tari_comms` P2P client: enough of the Noise_XX
// handshake and identity-exchange protocol to dial a Tari node/wallet peer and report back who
// it says it is.
//
// This package is a single-shot client probe only (P2P_SPEC.md section 10) -- it does not
// implement RPC-over-P2P (comms/core/src/protocol/rpc/*), full peer-management/address-book
// logic, or liveness-wire-mode. See p2p/VERIFICATION.md for exactly which primitives here are
// byte-exact verified against real Tari Rust source/test-vectors, and which are Go-only
// internally-consistent (not independently cross-checked, due to no Rust toolchain being
// available in the sandbox this package was originally written in).
package p2p

import (
	"context"
	"fmt"
	"net"
	"time"
)

// Probe dials addr (host:port), performs the network-wire-byte + Noise_XX handshake + identity
// exchange (P2P_SPEC.md sections 5-7), and returns the peer's identity info. It returns a clean
// error (never a panic) for unreachable hosts or non-Tari peers/protocol mismatches.
//
// Probe does not perform a live network probe as part of this package's own automated test
// suite (P2P_SPEC.md section 8 point 5) -- see p2p_test.go for an equivalent in-process
// initiator/responder test over the exact same code path (dial replaced by an in-memory pipe).
func Probe(ctx context.Context, addr string) (*PeerInfo, error) {
	start := time.Now()

	staticKeypair, err := GenerateRistrettoKeypair()
	if err != nil {
		return nil, fmt.Errorf("p2p: generating ephemeral static keypair for probe: %w", err)
	}

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("p2p: dialing %s: %w", addr, err)
	}
	defer conn.Close()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	session, err := InitiatorHandshake(ctx, conn, staticKeypair)
	if err != nil {
		return nil, fmt.Errorf("p2p: performing Noise_XX handshake with %s: %w", addr, err)
	}

	info, err := session.ExchangeIdentity(ctx)
	if err != nil {
		return nil, fmt.Errorf("p2p: exchanging identity with %s: %w", addr, err)
	}

	info.Latency = time.Since(start)
	return info, nil
}
