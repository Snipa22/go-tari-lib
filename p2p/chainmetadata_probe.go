package p2p

import (
	"context"
	"fmt"
	"net"
	"time"

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
// InitiatorHandshake, same pattern as Probe), then performs RPC-over-P2P protocol negotiation
// (`t/blksync/1`), the RPC session handshake, and a single get_chain_metadata call (see
// p2p/rpc), returning the peer's chain metadata.
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

	metadata, err := rpcpkg.GetChainMetadata(ctx, session)
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
