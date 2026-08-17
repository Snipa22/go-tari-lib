package p2p

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/hashicorp/yamux"

	rpcpkg "github.com/Snipa22/go-tari-lib/p2p/rpc"
)

// ChainMetadataInfo is the result of a successful ProbeChainMetadata call: the peer's decoded
// ChainMetadata (source: base_layer/core/src/base_node/proto/chain_metadata.proto), plus the
// round-trip latency, in the same spirit as PeerInfo/Probe.
type ChainMetadataInfo struct {
	BestBlockHeight           uint64
	BestBlockHash             []byte
	AccumulatedDifficultyLow  []byte
	AccumulatedDifficultyHigh []byte
	PrunedHeight              uint64
	Timestamp                 uint64

	Latency time.Duration
}

// ProbeChainMetadata dials addr (host:port), performs the Noise_XX handshake (reusing
// InitiatorHandshake, same pattern as Probe), opens a Yamux-multiplexed substream on top of that
// Noise session, and then performs RPC-over-P2P protocol negotiation (`t/blksync/1`), the RPC
// session handshake, and a single get_chain_metadata call (see p2p/rpc) over that substream,
// returning the peer's chain metadata.
//
// Real Tari nodes run protocol negotiation and RPC on a Yamux substream, not directly on the raw
// post-handshake Noise session (source: tari/comms/core/src/multiplexing/yamux.rs +
// tari/comms/core/src/connection_manager/peer_connection.rs) -- Yamux's own multiplexed byte
// stream is carried as the plaintext payload of Noise transport frames, i.e. it sits ON TOP of
// the encrypted Noise session, not instead of it. Wiring RPC-over-P2P directly onto
// Session.SendFrame/ReceiveFrame (as an earlier version of this function did) produces a stream
// that is missing this Yamux framing layer entirely, which real nodes reject/misparse (observed
// against real Tari mainnet nodes as "rpc: negotiation frame declares protocol id length 0 but
// 229 bytes follow the header" -- see p2p/VERIFICATION.md for the full writeup). See
// newSessionReadWriteCloser (p2p/yamuxadapter.go) and rpc.NewStreamTransport
// (p2p/rpc/streamtransport.go) for the two adapters that make this layering possible without
// rewriting negotiation.go/handshake.go/chainmetadata.go/canonicalframe.go's own frame
// encode/decode logic.
//
// Like Probe, this is a "poke and discard" single-shot client call -- no persistent connection
// management, single call, closes the connection when done.
func ProbeChainMetadata(ctx context.Context, addr string) (*ChainMetadataInfo, error) {
	start := time.Now()

	staticKeypair, err := GenerateRistrettoKeypair()
	if err != nil {
		return nil, fmt.Errorf("p2p: generating ephemeral static keypair for chain metadata probe: %w", err)
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
	defer session.Close()

	// Identity exchange must happen before the Yamux upgrade, matching real Tari's own
	// connection-establishment order (source: tari/comms/core/src/connection_manager/dialer.rs,
	// `perform_socket_upgrade_procedure`: identity exchange runs directly on the post-handshake
	// Noise session, and only once that -- plus the peer's own local validation of OUR identity
	// message, see p2p/identity_signature.go -- succeeds does either side proceed to the Yamux
	// substream multiplexing layer). Skipping this step (as an earlier version of this function
	// did) leaves the peer still waiting for our identity message while we instead go straight to
	// Yamux, which real nodes do not expect and will not complete.
	if _, err := session.ExchangeIdentity(ctx); err != nil {
		return nil, fmt.Errorf("p2p: exchanging identity with %s: %w", addr, err)
	}

	// Yamux multiplexes over the Noise session's own frame-oriented SendFrame/ReceiveFrame API
	// (adapted to a plain io.ReadWriteCloser byte stream by sessionReadWriteCloser), NOT over the
	// raw net.Conn -- Yamux's byte stream is the plaintext payload of Noise transport frames.
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

	metadata, err := rpcpkg.GetChainMetadata(ctx, transport)
	if err != nil {
		return nil, fmt.Errorf("p2p: getting chain metadata from %s: %w", addr, err)
	}

	return &ChainMetadataInfo{
		BestBlockHeight:           metadata.GetBestBlockHeight(),
		BestBlockHash:             metadata.GetBestBlockHash(),
		AccumulatedDifficultyLow:  metadata.GetAccumulatedDifficultyLow(),
		AccumulatedDifficultyHigh: metadata.GetAccumulatedDifficultyHigh(),
		PrunedHeight:              metadata.GetPrunedHeight(),
		Timestamp:                 metadata.GetTimestamp(),
		Latency:                   time.Since(start),
	}, nil
}
