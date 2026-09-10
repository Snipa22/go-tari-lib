package rpc

import (
	"fmt"

	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	googleproto "google.golang.org/protobuf/proto"
)

// ServeGetPeers performs the full RESPONDER side of the get_peers RPC over session, symmetric to
// the client-side GetPeers (dht_getpeers.go):
//
//  1. Negotiate DhtProtocolID ("t/dht/1") as the RESPONDER (NegotiateProtocolInbound, supporting
//     ONLY that one protocol id) -- if the peer requested any other protocol, this replies
//     NOT_SUPPORTED on the wire (exactly as real Tari's negotiation.rs sanctions for an
//     unsupported protocol -- no penalty/ban) and returns an error wrapping
//     ErrProtocolNotSupported without touching the RPC session handshake or reading any request.
//     This is deliberately the ONLY protocol-negotiation entry point a caller needs for this
//     responder role: driving substream protocol dispatch is as simple as calling ServeGetPeers
//     unconditionally on every accepted substream and closing just that substream on error (see
//     p2p.Serve).
//  2. Perform the RESPONDER side of the RPC session handshake (PerformSessionHandshakeResponder
//     -- unconditionally accepts SupportedRPCVersion).
//  3. Receive one canonical-framed RpcRequest, decode its payload as GetPeersRequest.
//  4. Bound peers (the caller-supplied, already time-windowed/known-good list) SERVER-SIDE
//     against the request's own N/MaxClaims/MaxAddressesPerClaim -- never trusting the caller to
//     have already bounded it (see boundPeersForRequest below for the exact truncation rules).
//  5. Stream the bounded list back as one RpcResponse per peer (flags=0, except the LAST message
//     -- which carries either the last peer's payload or, if the bounded list is empty, an
//     empty payload -- which has the FIN flag set). This "FIN on last payload" streaming style
//     mirrors real Tari's own `exceeded_message_size`-capable framing (see dht_getpeers.go's doc
//     comment on rpcResponseFlagFIN) and is exactly what
//     TestGetPeersHappyPathFINOnLastPayload/dht_getpeers_test.go already proves the client-side
//     GetPeers decodes correctly.
//
// session must already have completed the Noise_XX handshake (+, if wrapping a raw byte-stream
// substream rather than a *p2p.Session directly, be a Transport freshly constructed via
// NewStreamTransport, still in negotiation-framing mode -- ServeGetPeers itself calls
// BeginCanonicalFraming internally after negotiation succeeds, exactly like GetChainMetadata/
// GetPeers do on the client side).
func ServeGetPeers(session Transport, peers []*pb.PeerInfo) error {
	if _, err := NegotiateProtocolInbound(session, [][]byte{DhtProtocolID}); err != nil {
		return fmt.Errorf("rpc: negotiating protocol %q as responder: %w", DhtProtocolID, err)
	}
	BeginCanonicalFraming(session)

	if err := PerformSessionHandshakeResponder(session); err != nil {
		return fmt.Errorf("rpc: performing RPC session handshake as responder: %w", err)
	}

	inFrame, err := session.ReceiveFrame()
	if err != nil {
		return fmt.Errorf("rpc: receiving get_peers RpcRequest: %w", err)
	}
	reqBytes, err := DecodeCanonicalFrame(inFrame)
	if err != nil {
		return fmt.Errorf("rpc: decoding get_peers RpcRequest canonical frame: %w", err)
	}
	rpcReq := &pb.RpcRequest{}
	if err := googleproto.Unmarshal(reqBytes, rpcReq); err != nil {
		return fmt.Errorf("rpc: unmarshalling get_peers RpcRequest: %w", err)
	}
	getPeersReq := &pb.GetPeersRequest{}
	if len(rpcReq.GetPayload()) > 0 {
		if err := googleproto.Unmarshal(rpcReq.GetPayload(), getPeersReq); err != nil {
			return fmt.Errorf("rpc: unmarshalling GetPeersRequest payload: %w", err)
		}
	}

	bounded := boundPeersForRequest(peers, getPeersReq)

	if len(bounded) == 0 {
		resp := &pb.RpcResponse{RequestId: rpcReq.GetRequestId(), Status: 0, Flags: rpcResponseFlagFIN}
		respBytes, err := googleproto.Marshal(resp)
		if err != nil {
			return fmt.Errorf("rpc: marshalling empty get_peers RpcResponse: %w", err)
		}
		if err := session.SendFrame(EncodeCanonicalFrame(respBytes)); err != nil {
			return fmt.Errorf("rpc: sending empty get_peers RpcResponse: %w", err)
		}
		return nil
	}

	for i, peer := range bounded {
		getPeersResp := &pb.GetPeersResponse{Peer: peer}
		payload, err := googleproto.Marshal(getPeersResp)
		if err != nil {
			return fmt.Errorf("rpc: marshalling GetPeersResponse payload for peer %d: %w", i, err)
		}
		flags := uint32(0)
		if i == len(bounded)-1 {
			flags = rpcResponseFlagFIN
		}
		resp := &pb.RpcResponse{RequestId: rpcReq.GetRequestId(), Status: 0, Flags: flags, Payload: payload}
		respBytes, err := googleproto.Marshal(resp)
		if err != nil {
			return fmt.Errorf("rpc: marshalling get_peers RpcResponse for peer %d: %w", i, err)
		}
		if err := session.SendFrame(EncodeCanonicalFrame(respBytes)); err != nil {
			return fmt.Errorf("rpc: sending get_peers RpcResponse for peer %d: %w", i, err)
		}
	}
	return nil
}

// boundPeersForRequest returns a NEW slice (never mutating peers or any of its elements) of at
// most req.N peers (req.N == 0 means "no count bound", matching the real get_peers protocol's
// own n=0-means-all semantics -- see DefaultGetPeersRequest's doc comment in
// p2p/getpeers_probe.go for why THIS package's own client defaults away from that; the
// RESPONDER side has no business second-guessing what a peer actually asked for, only enforcing
// it), with each returned peer's Claims truncated to at most req.MaxClaims (0 means no bound)
// and each of THOSE claims' Addresses truncated to at most req.MaxAddressesPerClaim (0 means no
// bound).
//
// This exists so ServeGetPeers never trusts its caller (e.g. the responder loop in package p2p)
// to have already bounded the peer list it hands over -- the bounding happens here,
// server-side, against the specific request just received, every time.
func boundPeersForRequest(peers []*pb.PeerInfo, req *pb.GetPeersRequest) []*pb.PeerInfo {
	n := len(peers)
	if req.GetN() > 0 && uint32(n) > req.GetN() {
		n = int(req.GetN())
	}

	bounded := make([]*pb.PeerInfo, n)
	for i := 0; i < n; i++ {
		bounded[i] = boundPeerClaims(peers[i], req.GetMaxClaims(), req.GetMaxAddressesPerClaim())
	}
	return bounded
}

// boundPeerClaims returns a new *pb.PeerInfo with the same PublicKey as peer, but with Claims
// truncated to at most maxClaims entries (0 means no bound) and each of those claims' Addresses
// truncated to at most maxAddressesPerClaim entries (0 means no bound). peer itself, and its
// Claims slice/elements, are never mutated.
func boundPeerClaims(peer *pb.PeerInfo, maxClaims, maxAddressesPerClaim uint32) *pb.PeerInfo {
	if peer == nil {
		return nil
	}

	claims := peer.GetClaims()
	numClaims := len(claims)
	if maxClaims > 0 && uint32(numClaims) > maxClaims {
		numClaims = int(maxClaims)
	}

	boundedClaims := make([]*pb.PeerIdentityClaim, numClaims)
	for i := 0; i < numClaims; i++ {
		boundedClaims[i] = boundClaimAddresses(claims[i], maxAddressesPerClaim)
	}

	return &pb.PeerInfo{
		PublicKey: peer.GetPublicKey(),
		Claims:    boundedClaims,
	}
}

// boundClaimAddresses returns a new *pb.PeerIdentityClaim with the same PeerFeatures/
// IdentitySignature as claim, but Addresses truncated to at most maxAddressesPerClaim entries (0
// means no bound). claim itself, and its Addresses slice, are never mutated.
func boundClaimAddresses(claim *pb.PeerIdentityClaim, maxAddressesPerClaim uint32) *pb.PeerIdentityClaim {
	if claim == nil {
		return nil
	}

	addresses := claim.GetAddresses()
	numAddresses := len(addresses)
	if maxAddressesPerClaim > 0 && uint32(numAddresses) > maxAddressesPerClaim {
		numAddresses = int(maxAddressesPerClaim)
	}

	boundedAddresses := make([][]byte, numAddresses)
	copy(boundedAddresses, addresses[:numAddresses])

	return &pb.PeerIdentityClaim{
		Addresses:         boundedAddresses,
		PeerFeatures:      claim.GetPeerFeatures(),
		IdentitySignature: claim.GetIdentitySignature(),
	}
}
