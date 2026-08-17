package rpc

import (
	"context"
	"fmt"

	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	googleproto "google.golang.org/protobuf/proto"
)

// BlockSyncProtocolID is the protocol id negotiated before issuing get_chain_metadata (source:
// `#[tari_rpc(protocol_name = b"t/blksync/1", ...)]` on the `BaseNodeSyncService` trait,
// base_layer/core/src/base_node/sync/rpc/mod.rs).
var BlockSyncProtocolID = []byte("t/blksync/1")

// getChainMetadataMethod is the RPC method number for get_chain_metadata (source:
// `#[rpc(method = 5)] async fn get_chain_metadata` on `BaseNodeSyncService`; other methods on the
// same trait are 1,2,3,4,6,8 -- method numbers are explicit per-method attributes, not
// sequential/inferred).
const getChainMetadataMethod uint32 = 5

// defaultRequestID is the request_id we use for the single get_chain_metadata request this
// package ever issues per Session (no concurrent multi-request pipelining is implemented).
const defaultRequestID uint32 = 1

// defaultRPCDeadlineSeconds is the deadline (in seconds, matching the protobuf field's u64
// second-granularity semantics) attached to the get_chain_metadata request.
const defaultRPCDeadlineSeconds uint64 = 20

// RPCStatusError is returned by GetChainMetadata when the peer's RpcResponse.status is non-zero.
// Per p2p/RPC_TOR_SPEC.md section A3, the format of the error payload for a non-zero status is
// not specified/needed here, so only the raw status code is surfaced.
type RPCStatusError struct {
	Status uint32
}

func (e *RPCStatusError) Error() string {
	return fmt.Sprintf("rpc: get_chain_metadata failed with non-zero RpcResponse.status=%d", e.Status)
}

// GetChainMetadata performs the full get_chain_metadata RPC call over session (source:
// base_layer/core/src/base_node/sync/rpc/mod.rs +
// base_layer/core/src/base_node/proto/chain_metadata.proto):
//
//  1. Negotiate BlockSyncProtocolID ("t/blksync/1").
//  2. Perform the RPC session handshake.
//  3. Build+send RpcRequest{request_id, method: 5, flags: 0, deadline, payload: []byte{}}
//     (empty payload -- the real Rust `Request<()>`, `()` encodes to zero protobuf bytes).
//  4. Receive+decode RpcResponse. Check status first: non-zero -> *RPCStatusError (payload not
//     decoded in that case). Zero -> decode payload as ChainMetadata.
//
// Between steps 1 and 2, GetChainMetadata calls BeginCanonicalFraming(session): if session is a
// streamTransport (i.e. this call is running over a raw byte-stream Yamux substream, via
// NewStreamTransport -- see p2p.ProbeChainMetadata), this signals the transition from
// negotiation-frame parsing to canonical-frame parsing on that shared substream (see
// streamtransport.go's doc comments for why this signal is needed at all). It's a no-op for
// Transport implementations that don't need it (e.g. this package's own tests operating directly
// on a *p2p.Session).
//
// ctx is currently only checked for cancellation before starting (no per-step deadline plumbing
// into Session.SendFrame/ReceiveFrame, which are synchronous blocking calls on the underlying
// net.Conn -- callers that need a hard deadline should set one on the connection directly, e.g.
// via conn.SetDeadline before constructing the Session, matching how p2p.Probe does it).
func GetChainMetadata(ctx context.Context, session Transport) (*pb.ChainMetadata, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("rpc: context done before starting get_chain_metadata: %w", ctx.Err())
	default:
	}

	if err := NegotiateProtocol(session, BlockSyncProtocolID); err != nil {
		return nil, fmt.Errorf("rpc: negotiating protocol %q: %w", BlockSyncProtocolID, err)
	}
	BeginCanonicalFraming(session)

	if _, err := PerformSessionHandshake(session); err != nil {
		return nil, fmt.Errorf("rpc: performing RPC session handshake: %w", err)
	}

	req := &pb.RpcRequest{
		RequestId: defaultRequestID,
		Method:    getChainMetadataMethod,
		Flags:     0,
		Deadline:  defaultRPCDeadlineSeconds,
		Payload:   []byte{},
	}
	reqBytes, err := googleproto.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("rpc: marshalling get_chain_metadata RpcRequest: %w", err)
	}
	if err := session.SendFrame(EncodeCanonicalFrame(reqBytes)); err != nil {
		return nil, fmt.Errorf("rpc: sending get_chain_metadata RpcRequest: %w", err)
	}

	inFrame, err := session.ReceiveFrame()
	if err != nil {
		return nil, fmt.Errorf("rpc: receiving get_chain_metadata RpcResponse: %w", err)
	}
	respBytes, err := DecodeCanonicalFrame(inFrame)
	if err != nil {
		return nil, fmt.Errorf("rpc: decoding get_chain_metadata RpcResponse canonical frame: %w", err)
	}
	resp := &pb.RpcResponse{}
	if err := googleproto.Unmarshal(respBytes, resp); err != nil {
		return nil, fmt.Errorf("rpc: unmarshalling get_chain_metadata RpcResponse: %w", err)
	}

	if resp.GetStatus() != 0 {
		return nil, &RPCStatusError{Status: resp.GetStatus()}
	}

	metadata := &pb.ChainMetadata{}
	if err := googleproto.Unmarshal(resp.GetPayload(), metadata); err != nil {
		return nil, fmt.Errorf("rpc: unmarshalling ChainMetadata payload: %w", err)
	}
	return metadata, nil
}
