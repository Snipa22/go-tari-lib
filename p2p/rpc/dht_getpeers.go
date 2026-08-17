package rpc

import (
	"context"
	"errors"
	"fmt"

	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	googleproto "google.golang.org/protobuf/proto"
)

// DhtProtocolID is the protocol id negotiated before issuing get_peers (source:
// `#[tari_rpc(protocol_name = b"t/dht/1", ...)]` on the DHT RPC service trait,
// comms/dht/src/rpc/mod.rs). This is a SEPARATE RPC service from get_chain_metadata's
// `t/blksync/1` -- method numbers are per-trait, not global, so getPeersMethod below (10)
// coexists with getChainMetadataMethod (5, chainmetadata.go) without conflict.
var DhtProtocolID = []byte("t/dht/1")

// getPeersMethod is the RPC method number for get_peers on the t/dht/1 service (source:
// `#[rpc(method = 10)] async fn get_peers`, comms/dht/src/rpc/mod.rs).
const getPeersMethod uint32 = 10

// rpcResponseFlagFIN is the FIN bit on RpcResponse.flags, signalling the last message of a
// streaming RPC response (source: comms/core/src/protocol/rpc/message.rs,
// `bitflags! { pub struct RpcMessageFlags: u8 { const FIN = 0x01; const ACK = 0x02; } }` and
// `RpcResponse::is_fin`). A FIN-flagged response MAY also carry a real, non-empty payload (see
// the real `exceeded_message_size` constructor in that same source file, which sets
// `flags: RpcMessageFlags::FIN` together with a real payload) -- GetPeers below decodes any
// non-empty payload on every response BEFORE checking the FIN flag, precisely to handle that
// case correctly rather than assuming FIN always means "empty terminator".
const rpcResponseFlagFIN uint32 = 0x01

// maxGetPeersStreamIterations caps the number of RpcResponse messages GetPeers will read while
// waiting for a FIN-flagged response, before giving up. This guards against a buggy or
// malicious peer that never sets FIN on a streaming response -- without this cap, GetPeers would
// loop forever (ReceiveFrame blocks on the underlying connection, so a peer that keeps sending
// non-FIN frames forever would otherwise hang this call indefinitely rather than erroring out).
// 100000 is comfortably above any plausible real peer list size (see
// DefaultGetPeersRequest's own, much smaller, n=50 cap in p2p/getpeers_probe.go) while still
// bounding worst-case memory/time for a hostile peer.
const maxGetPeersStreamIterations = 100000

// GetPeersRequest is the set of parameters for a get_peers call (source:
// comms/dht/src/proto/rpc.proto, message GetPeersRequest -- see p2p/proto/dht_rpc.proto for the
// vendored proto and pb.GetPeersRequest for the generated wire type this gets marshalled into).
type GetPeersRequest struct {
	// N is the maximum number of peers requested. Per the real protocol, n=0 means "all known
	// peers" -- see DefaultGetPeersRequest in p2p/getpeers_probe.go for why this client defaults
	// to a bounded, non-zero value instead.
	N uint32
	// IncludeClients requests that client (non-node) peers also be included in the response.
	IncludeClients bool
	// MaxClaims bounds the number of PeerIdentityClaim entries returned per peer.
	MaxClaims uint32
	// MaxAddressesPerClaim bounds the number of addresses returned per claim.
	MaxAddressesPerClaim uint32
}

// GetPeers performs the full get_peers RPC call over session (source:
// comms/dht/src/rpc/mod.rs + comms/dht/src/proto/rpc.proto):
//
//  1. Negotiate DhtProtocolID ("t/dht/1").
//  2. Perform the RPC session handshake.
//  3. Build+send RpcRequest{request_id: defaultRequestID, method: 10, flags: 0,
//     deadline: defaultRPCDeadlineSeconds, payload: <marshaled GetPeersRequest>}, canonical-framed
//     (mirroring GetChainMetadata's request-building style exactly, including reuse of that
//     function's defaultRequestID/defaultRPCDeadlineSeconds constants -- see chainmetadata.go).
//  4. Loop receiving canonical-framed RpcResponse messages: non-zero status -> *RPCStatusError
//     (same type GetChainMetadata uses); a non-empty payload on ANY response (FIN-flagged or not)
//     is decoded as a GetPeersResponse and its PeerInfo (if non-nil) appended to the result;
//     looping stops as soon as a response with the FIN flag set is observed, whether or not that
//     same response also carried a payload.
//
// See GetChainMetadata's doc comment for the shared BeginCanonicalFraming/ctx-cancellation
// semantics, which apply identically here.
func GetPeers(ctx context.Context, session Transport, req GetPeersRequest) ([]*pb.PeerInfo, error) {
	select {
	case <-ctx.Done():
		return nil, fmt.Errorf("rpc: context done before starting get_peers: %w", ctx.Err())
	default:
	}

	if err := NegotiateProtocol(session, DhtProtocolID); err != nil {
		return nil, fmt.Errorf("rpc: negotiating protocol %q: %w", DhtProtocolID, err)
	}
	BeginCanonicalFraming(session)

	if _, err := PerformSessionHandshake(session); err != nil {
		return nil, fmt.Errorf("rpc: performing RPC session handshake: %w", err)
	}

	payload := &pb.GetPeersRequest{
		N:                    req.N,
		IncludeClients:       req.IncludeClients,
		MaxClaims:            req.MaxClaims,
		MaxAddressesPerClaim: req.MaxAddressesPerClaim,
	}
	payloadBytes, err := googleproto.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("rpc: marshalling get_peers GetPeersRequest: %w", err)
	}

	rpcReq := &pb.RpcRequest{
		RequestId: defaultRequestID,
		Method:    getPeersMethod,
		Flags:     0,
		Deadline:  defaultRPCDeadlineSeconds,
		Payload:   payloadBytes,
	}
	rpcReqBytes, err := googleproto.Marshal(rpcReq)
	if err != nil {
		return nil, fmt.Errorf("rpc: marshalling get_peers RpcRequest: %w", err)
	}
	if err := session.SendFrame(EncodeCanonicalFrame(rpcReqBytes)); err != nil {
		return nil, fmt.Errorf("rpc: sending get_peers RpcRequest: %w", err)
	}

	var peers []*pb.PeerInfo
	for i := 0; ; i++ {
		if i >= maxGetPeersStreamIterations {
			return nil, errors.New("rpc: get_peers stream exceeded max iterations without FIN")
		}

		inFrame, err := session.ReceiveFrame()
		if err != nil {
			return nil, fmt.Errorf("rpc: receiving get_peers RpcResponse: %w", err)
		}
		respBytes, err := DecodeCanonicalFrame(inFrame)
		if err != nil {
			return nil, fmt.Errorf("rpc: decoding get_peers RpcResponse canonical frame: %w", err)
		}
		resp := &pb.RpcResponse{}
		if err := googleproto.Unmarshal(respBytes, resp); err != nil {
			return nil, fmt.Errorf("rpc: unmarshalling get_peers RpcResponse: %w", err)
		}

		if resp.GetStatus() != 0 {
			return nil, &RPCStatusError{Status: resp.GetStatus()}
		}

		if len(resp.GetPayload()) > 0 {
			getPeersResp := &pb.GetPeersResponse{}
			if err := googleproto.Unmarshal(resp.GetPayload(), getPeersResp); err != nil {
				return nil, fmt.Errorf("rpc: unmarshalling GetPeersResponse payload: %w", err)
			}
			if peer := getPeersResp.GetPeer(); peer != nil {
				peers = append(peers, peer)
			}
		}

		if resp.GetFlags()&rpcResponseFlagFIN != 0 {
			break
		}
	}

	return peers, nil
}
