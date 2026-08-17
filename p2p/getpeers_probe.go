package p2p

import (
	"context"
	"fmt"

	"github.com/hashicorp/yamux"

	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	rpcpkg "github.com/Snipa22/go-tari-lib/p2p/rpc"
)

// DefaultGetPeersRequest returns a bounded, conservative default set of get_peers parameters:
// N=50, IncludeClients=false, MaxClaims=10, MaxAddressesPerClaim=10. This is deliberately NOT
// the real protocol's own "give me everything" default -- n=0 in the real t/dht/1 get_peers
// protocol means "all known peers" (comms/dht/src/rpc/mod.rs), which this client avoids
// defaulting to since an unbounded/absurd response from a misbehaving or hostile peer could
// otherwise consume unbounded memory/time on this end (see also GetPeers's own
// maxGetPeersStreamIterations cap in p2p/rpc/dht_getpeers.go, which guards the same class of
// concern from a different angle: a peer that never sends FIN, rather than one that sends an
// enormous number of peers before it does).
func DefaultGetPeersRequest() rpcpkg.GetPeersRequest {
	return rpcpkg.GetPeersRequest{
		N:                    50,
		IncludeClients:       false,
		MaxClaims:            10,
		MaxAddressesPerClaim: 10,
	}
}

// ProbeGetPeers is a thin wrapper around
// ProbeGetPeersWithOptions(ctx, addr, req, ProbeOptions{}) -- its exact existing signature and
// zero-config behavior (always dial directly, no SOCKS proxy) is unchanged; see
// ProbeGetPeersWithOptions for `.onion`/SOCKS5 support (dialForProbe in p2p/socks.go).
func ProbeGetPeers(ctx context.Context, addr string, req rpcpkg.GetPeersRequest) ([]*pb.PeerInfo, error) {
	return ProbeGetPeersWithOptions(ctx, addr, req, ProbeOptions{})
}

// ProbeGetPeersWithOptions dials addr (host:port), performs the Noise_XX handshake and identity
// exchange (reusing InitiatorHandshake/ExchangeIdentity, same pattern as
// ProbeChainMetadataWithOptions), opens a Yamux-multiplexed substream on top of that Noise
// session, and then performs RPC-over-P2P protocol negotiation (`t/dht/1`), the RPC session
// handshake, and a single streaming get_peers call (see p2p/rpc.GetPeers) over that substream,
// returning the peer's reported peer list. Like ProbeWithOptions, opts currently only configures
// SOCKS5 dialing for `.onion` addresses (see ProbeOptions and dialForProbe in socks.go); with the
// zero value of ProbeOptions, ProbeGetPeersWithOptions behaves identically to ProbeGetPeers.
//
// This mirrors p2p/chainmetadata_probe.go's ProbeChainMetadataWithOptions structure exactly
// (dial -> InitiatorHandshake -> ExchangeIdentity -> Yamux client + Open -> NewStreamTransport ->
// the package rpc call) -- see that file's doc comment for why each of those steps is required
// (Yamux multiplexing layer + identity exchange ordering, both confirmed against real Tari
// mainnet nodes for get_chain_metadata; see p2p/VERIFICATION.md's Part C/D addenda). This
// function has NOT itself been re-verified against a real Tari mainnet node -- see
// p2p/VERIFICATION.md's Part E addendum.
//
// Unlike ChainMetadataInfo, this returns the generated protobuf []*pb.PeerInfo type directly
// rather than a hand-flattened struct: PeerInfo's nested claims/addresses/identity-signature
// shape isn't worth flattening for a v1 of this call.
func ProbeGetPeersWithOptions(ctx context.Context, addr string, req rpcpkg.GetPeersRequest, opts ProbeOptions) ([]*pb.PeerInfo, error) {
	staticKeypair, err := GenerateRistrettoKeypair()
	if err != nil {
		return nil, fmt.Errorf("p2p: generating ephemeral static keypair for get_peers probe: %w", err)
	}

	conn, err := dialForProbe(ctx, addr, opts)
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
	defer session.Close()

	// Identity exchange must happen before the Yamux upgrade -- see
	// ProbeChainMetadataWithOptions's doc comment (p2p/chainmetadata_probe.go) and
	// p2p/VERIFICATION.md's Part D addendum for the full explanation and the real-node bug this
	// order fixed for get_chain_metadata.
	if _, err := session.ExchangeIdentity(ctx); err != nil {
		return nil, fmt.Errorf("p2p: exchanging identity with %s: %w", addr, err)
	}

	adapter := newSessionReadWriteCloser(session)
	yamuxSession, err := yamux.Client(adapter, nil)
	if err != nil {
		return nil, fmt.Errorf("p2p: establishing Yamux client session with %s: %w", addr, err)
	}
	defer yamuxSession.Close()

	stream, err := yamuxSession.Open()
	if err != nil {
		return nil, fmt.Errorf("p2p: opening Yamux substream to %s: %w", addr, err)
	}
	defer stream.Close()

	transport := rpcpkg.NewStreamTransport(stream)

	peers, err := rpcpkg.GetPeers(ctx, transport, req)
	if err != nil {
		return nil, fmt.Errorf("p2p: getting peers from %s: %w", addr, err)
	}

	return peers, nil
}
