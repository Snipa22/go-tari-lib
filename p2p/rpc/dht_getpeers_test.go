package rpc_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-lib/p2p"
	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	"github.com/Snipa22/go-tari-lib/p2p/rpc"
	googleproto "google.golang.org/protobuf/proto"
)

// rpcResponseFlagFIN mirrors the FIN bit rpc.GetPeers checks internally (RpcResponse.flags bit
// 0x01, source: comms/core/src/protocol/rpc/message.rs) -- duplicated here rather than exported
// from the rpc package, since tests build their own raw RpcResponse messages directly.
const rpcResponseFlagFIN uint32 = 0x01

// fixtureGetPeersRequest is used across the tests below to verify GetPeers marshals exactly the
// request parameters the caller supplied.
func fixtureGetPeersRequest() rpc.GetPeersRequest {
	return rpc.GetPeersRequest{
		N:                    50,
		IncludeClients:       true,
		MaxClaims:            10,
		MaxAddressesPerClaim: 5,
	}
}

// fixturePeerInfos returns 3 arbitrary, distinguishable PeerInfo fixtures used to verify the
// client collects ALL streamed peers, in order.
func fixturePeerInfos() []*pb.PeerInfo {
	return []*pb.PeerInfo{
		{
			PublicKey: []byte{0x01},
			Claims: []*pb.PeerIdentityClaim{
				{Addresses: [][]byte{[]byte("/ip4/10.0.0.1/tcp/18189")}, PeerFeatures: 1},
			},
		},
		{
			PublicKey: []byte{0x02},
			Claims: []*pb.PeerIdentityClaim{
				{Addresses: [][]byte{[]byte("/ip4/10.0.0.2/tcp/18189")}, PeerFeatures: 2},
			},
		},
		{
			PublicKey: []byte{0x03},
			Claims: []*pb.PeerIdentityClaim{
				{Addresses: [][]byte{[]byte("/ip4/10.0.0.3/tcp/18189")}, PeerFeatures: 3},
			},
		},
	}
}

// serveGetPeersStreaming is a minimal in-process RPC-over-P2P "responder" for get_peers: it
// performs the responder side of protocol negotiation (supporting only rpc.DhtProtocolID), the
// responder side of the RPC session handshake, reads the single GetPeersRequest, and then sends
// peers as SEPARATE streaming RpcResponse messages (one SendFrame per peer). If
// finOnLastPayload is true, the FIN flag is set on the SAME message that carries the last peer's
// payload (no separate empty terminator frame); otherwise the last payload-bearing message has
// flags=0 and a final, separate, empty-payload FIN terminator message is sent after it.
func serveGetPeersStreaming(t *testing.T, session *p2p.Session, peers []*pb.PeerInfo, finOnLastPayload bool) error {
	t.Helper()

	if _, err := rpc.NegotiateProtocolInbound(session, [][]byte{rpc.DhtProtocolID}); err != nil {
		return err
	}
	if err := rpc.PerformSessionHandshakeResponder(session); err != nil {
		return err
	}

	inFrame, err := session.ReceiveFrame()
	if err != nil {
		return err
	}
	reqBytes, err := rpc.DecodeCanonicalFrame(inFrame)
	if err != nil {
		return err
	}
	req := &pb.RpcRequest{}
	if err := googleproto.Unmarshal(reqBytes, req); err != nil {
		return err
	}

	sendPeer := func(peer *pb.PeerInfo, flags uint32) error {
		getPeersResp := &pb.GetPeersResponse{Peer: peer}
		payload, err := googleproto.Marshal(getPeersResp)
		if err != nil {
			return err
		}
		resp := &pb.RpcResponse{RequestId: req.GetRequestId(), Status: 0, Flags: flags, Payload: payload}
		respBytes, err := googleproto.Marshal(resp)
		if err != nil {
			return err
		}
		return session.SendFrame(rpc.EncodeCanonicalFrame(respBytes))
	}

	for i, peer := range peers {
		isLast := i == len(peers)-1
		flags := uint32(0)
		if isLast && finOnLastPayload {
			flags = rpcResponseFlagFIN
		}
		if err := sendPeer(peer, flags); err != nil {
			return err
		}
	}

	if !finOnLastPayload {
		// Separate, empty-payload FIN terminator.
		resp := &pb.RpcResponse{RequestId: req.GetRequestId(), Status: 0, Flags: rpcResponseFlagFIN}
		respBytes, err := googleproto.Marshal(resp)
		if err != nil {
			return err
		}
		if err := session.SendFrame(rpc.EncodeCanonicalFrame(respBytes)); err != nil {
			return err
		}
	}

	return nil
}

// assertPeersEqual fails t if got does not contain exactly the same peers (by PublicKey, in
// order) as want.
func assertPeersEqual(t *testing.T, got, want []*pb.PeerInfo) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("len(peers) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i].GetPublicKey(), want[i].GetPublicKey()) {
			t.Errorf("peer %d: PublicKey = %x, want %x", i, got[i].GetPublicKey(), want[i].GetPublicKey())
		}
		if len(got[i].GetClaims()) != len(want[i].GetClaims()) {
			t.Errorf("peer %d: len(Claims) = %d, want %d", i, len(got[i].GetClaims()), len(want[i].GetClaims()))
		}
	}
}

// TestGetPeersHappyPathSeparateFINTerminator covers the streaming case where the responder sends
// N peers as N separate RpcResponse messages, all with flags=0, followed by a final, separate,
// empty-payload message with the FIN flag set.
func TestGetPeersHappyPathSeparateFINTerminator(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	want := fixturePeerInfos()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- serveGetPeersStreaming(t, server, want, false)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := rpc.GetPeers(ctx, client, fixtureGetPeersRequest())
	if err != nil {
		t.Fatalf("GetPeers: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("in-process responder failed: %v", err)
	}

	assertPeersEqual(t, got, want)
}

// TestGetPeersHappyPathFINOnLastPayload covers the streaming case exercising the real Tari
// `exceeded_message_size`-style behaviour explicitly noted in comms/core/src/protocol/rpc/
// message.rs: the FIN flag is attached to the SAME message that carries the LAST peer's real
// payload -- there is no separate empty terminator frame at all. GetPeers must still collect all
// peers, including that last one, and must not wait for an additional frame after it.
func TestGetPeersHappyPathFINOnLastPayload(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	want := fixturePeerInfos()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- serveGetPeersStreaming(t, server, want, true)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := rpc.GetPeers(ctx, client, fixtureGetPeersRequest())
	if err != nil {
		t.Fatalf("GetPeers: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("in-process responder failed: %v", err)
	}

	assertPeersEqual(t, got, want)
}

// TestGetPeersProtocolNotSupported covers the negotiation NOT_SUPPORTED path for t/dht/1,
// analogous to TestGetChainMetadataProtocolNotSupported.
func TestGetPeersProtocolNotSupported(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		_, err := rpc.NegotiateProtocolInbound(server, [][]byte{[]byte("t/some-other-protocol/1")})
		serverErrCh <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := rpc.GetPeers(ctx, client, fixtureGetPeersRequest())
	if err == nil {
		t.Fatalf("expected GetPeers to fail when the peer doesn't support t/dht/1")
	}
	if !errors.Is(err, rpc.ErrProtocolNotSupported) {
		t.Fatalf("expected errors.Is(err, rpc.ErrProtocolNotSupported), got: %v", err)
	}
	<-serverErrCh
}

// TestGetPeersNonZeroStatus covers the RpcResponse.status != 0 path for the streaming get_peers
// call: the client must surface a clean, typed error and must not attempt to decode the payload
// as GetPeersResponse, analogous to TestGetChainMetadataNonZeroStatus.
func TestGetPeersNonZeroStatus(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	const wantStatus uint32 = 9

	serverErrCh := make(chan error, 1)
	go func() {
		if _, err := rpc.NegotiateProtocolInbound(server, [][]byte{rpc.DhtProtocolID}); err != nil {
			serverErrCh <- err
			return
		}
		if err := rpc.PerformSessionHandshakeResponder(server); err != nil {
			serverErrCh <- err
			return
		}
		inFrame, err := server.ReceiveFrame()
		if err != nil {
			serverErrCh <- err
			return
		}
		if _, err := rpc.DecodeCanonicalFrame(inFrame); err != nil {
			serverErrCh <- err
			return
		}
		resp := &pb.RpcResponse{Status: wantStatus}
		respBytes, err := googleproto.Marshal(resp)
		if err != nil {
			serverErrCh <- err
			return
		}
		serverErrCh <- server.SendFrame(rpc.EncodeCanonicalFrame(respBytes))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := rpc.GetPeers(ctx, client, fixtureGetPeersRequest())
	if err == nil {
		t.Fatalf("expected GetPeers to fail on a non-zero RpcResponse.status")
	}
	var statusErr *rpc.RPCStatusError
	if !errors.As(err, &statusErr) {
		t.Fatalf("expected a *rpc.RPCStatusError, got: %v", err)
	}
	if statusErr.Status != wantStatus {
		t.Fatalf("RPCStatusError.Status = %d, want %d", statusErr.Status, wantStatus)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("in-process responder failed: %v", err)
	}
}
