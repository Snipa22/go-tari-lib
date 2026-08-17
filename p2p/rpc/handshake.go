package rpc

import (
	"fmt"

	rpcpb "github.com/Snipa22/go-tari-lib/p2p/proto"
	googleproto "google.golang.org/protobuf/proto"
)

// SupportedRPCVersion is the only RPC version this client offers during the session handshake.
const SupportedRPCVersion uint32 = 0

// HandshakeRejectedError is returned by PerformSessionHandshake when the peer rejects the RPC
// session handshake (source: tari/comms/core/src/protocol/rpc/handshake.rs,
// `perform_client_handshake`, the `Rejected` branch of `RpcSessionReply.session_result`). This is
// an EXPECTED, non-fatal outcome (e.g. the peer is at capacity), not a panic/fatal error --
// callers can inspect Reason to see why.
type HandshakeRejectedError struct {
	Reason rpcpb.RpcSessionReply_HandshakeRejectReason
}

func (e *HandshakeRejectedError) Error() string {
	return fmt.Sprintf("rpc: peer rejected RPC session handshake: %s", e.Reason)
}

// PerformSessionHandshake performs the CLIENT side of the RPC session handshake over session
// (source: tari/comms/core/src/protocol/rpc/handshake.rs, `perform_client_handshake`):
//
//  1. Send a canonical-framed RpcSession{supported_versions: [0]}.
//  2. Read back one canonical frame, decode as RpcSessionReply.
//  3. session_result oneof:
//     - AcceptedVersion(u32) -> success, return that version (will be 0).
//     - Rejected(true) -> read reject_reason -> return a *HandshakeRejectedError.
//
// session must already have completed protocol negotiation (see NegotiateProtocol) for
// `t/blksync/1` before this is called.
func PerformSessionHandshake(session Transport) (rpcVersion uint32, err error) {
	sessionMsg := &rpcpb.RpcSession{SupportedVersions: []uint32{SupportedRPCVersion}}
	sessionMsgBytes, err := googleproto.Marshal(sessionMsg)
	if err != nil {
		return 0, fmt.Errorf("rpc: marshalling RpcSession: %w", err)
	}
	if err := session.SendFrame(EncodeCanonicalFrame(sessionMsgBytes)); err != nil {
		return 0, fmt.Errorf("rpc: sending RpcSession handshake frame: %w", err)
	}

	inFrame, err := session.ReceiveFrame()
	if err != nil {
		return 0, fmt.Errorf("rpc: receiving RpcSessionReply: %w", err)
	}
	replyBytes, err := DecodeCanonicalFrame(inFrame)
	if err != nil {
		return 0, fmt.Errorf("rpc: decoding RpcSessionReply canonical frame: %w", err)
	}
	reply := &rpcpb.RpcSessionReply{}
	if err := googleproto.Unmarshal(replyBytes, reply); err != nil {
		return 0, fmt.Errorf("rpc: unmarshalling RpcSessionReply: %w", err)
	}

	switch result := reply.GetSessionResult().(type) {
	case *rpcpb.RpcSessionReply_AcceptedVersion:
		return result.AcceptedVersion, nil
	case *rpcpb.RpcSessionReply_Rejected:
		if !result.Rejected {
			return 0, fmt.Errorf("rpc: RpcSessionReply.session_result was Rejected(false), which is not a valid handshake outcome")
		}
		return 0, &HandshakeRejectedError{Reason: reply.GetRejectReason()}
	default:
		return 0, fmt.Errorf("rpc: RpcSessionReply had neither accepted_version nor rejected set")
	}
}

// PerformSessionHandshakeResponder performs the RESPONDER side of the RPC session handshake,
// unconditionally accepting SupportedRPCVersion. Provided to support this package's own
// in-process tests (see p2p/RPC_TOR_SPEC.md section A4); a real server/responder role is out of
// scope for this client.
func PerformSessionHandshakeResponder(session Transport) error {
	inFrame, err := session.ReceiveFrame()
	if err != nil {
		return fmt.Errorf("rpc: receiving RpcSession: %w", err)
	}
	reqBytes, err := DecodeCanonicalFrame(inFrame)
	if err != nil {
		return fmt.Errorf("rpc: decoding RpcSession canonical frame: %w", err)
	}
	req := &rpcpb.RpcSession{}
	if err := googleproto.Unmarshal(reqBytes, req); err != nil {
		return fmt.Errorf("rpc: unmarshalling RpcSession: %w", err)
	}

	reply := &rpcpb.RpcSessionReply{
		SessionResult: &rpcpb.RpcSessionReply_AcceptedVersion{AcceptedVersion: SupportedRPCVersion},
	}
	replyBytes, err := googleproto.Marshal(reply)
	if err != nil {
		return fmt.Errorf("rpc: marshalling RpcSessionReply: %w", err)
	}
	if err := session.SendFrame(EncodeCanonicalFrame(replyBytes)); err != nil {
		return fmt.Errorf("rpc: sending RpcSessionReply: %w", err)
	}
	return nil
}

// RejectSessionHandshakeResponder performs the RESPONDER side of the RPC session handshake,
// rejecting the client's request with the given reason. Provided to support this package's own
// in-process tests of the rejection path.
func RejectSessionHandshakeResponder(session Transport, reason rpcpb.RpcSessionReply_HandshakeRejectReason) error {
	inFrame, err := session.ReceiveFrame()
	if err != nil {
		return fmt.Errorf("rpc: receiving RpcSession: %w", err)
	}
	if _, err := DecodeCanonicalFrame(inFrame); err != nil {
		return fmt.Errorf("rpc: decoding RpcSession canonical frame: %w", err)
	}

	reply := &rpcpb.RpcSessionReply{
		SessionResult: &rpcpb.RpcSessionReply_Rejected{Rejected: true},
		RejectReason:  reason,
	}
	replyBytes, err := googleproto.Marshal(reply)
	if err != nil {
		return fmt.Errorf("rpc: marshalling rejecting RpcSessionReply: %w", err)
	}
	if err := session.SendFrame(EncodeCanonicalFrame(replyBytes)); err != nil {
		return fmt.Errorf("rpc: sending rejecting RpcSessionReply: %w", err)
	}
	return nil
}
