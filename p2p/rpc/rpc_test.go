package rpc_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-lib/p2p"
	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	"github.com/Snipa22/go-tari-lib/p2p/rpc"
	googleproto "google.golang.org/protobuf/proto"
)

// handshakeBothSides completes the Noise_XX handshake on both ends of an in-memory net.Pipe(),
// returning the client (initiator) and server (responder) Sessions. Mirrors the pattern used by
// p2p/p2p_test.go's TestInitiatorResponderNoiseXXAndIdentityExchange.
func handshakeBothSides(t *testing.T) (client, server *p2p.Session) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { clientConn.Close(); serverConn.Close() })

	clientStatic, err := p2p.GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating client static keypair: %v", err)
	}
	serverStatic, err := p2p.GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating server static keypair: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		session *p2p.Session
		err     error
	}
	clientCh := make(chan result, 1)
	serverCh := make(chan result, 1)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s, err := p2p.InitiatorHandshake(ctx, clientConn, clientStatic, p2p.NetworkByteMainNet)
		clientCh <- result{s, err}
	}()
	go func() {
		defer wg.Done()
		s, err := p2p.ResponderHandshake(ctx, serverConn, serverStatic)
		serverCh <- result{s, err}
	}()
	wg.Wait()

	clientRes := <-clientCh
	serverRes := <-serverCh
	if clientRes.err != nil {
		t.Fatalf("client Noise handshake failed: %v", clientRes.err)
	}
	if serverRes.err != nil {
		t.Fatalf("server Noise handshake failed: %v", serverRes.err)
	}
	return clientRes.session, serverRes.session
}

// fixtureChainMetadata is an arbitrary, fully-populated ChainMetadata used across the tests
// below to verify the client decodes exactly what the (fake) responder sent.
func fixtureChainMetadata() *pb.ChainMetadata {
	return &pb.ChainMetadata{
		BestBlockHeight:           123456,
		BestBlockHash:             []byte{0x01, 0x02, 0x03, 0x04},
		AccumulatedDifficultyLow:  []byte{0xAA, 0xBB},
		AccumulatedDifficultyHigh: []byte{0xCC, 0xDD},
		PrunedHeight:              100,
		Timestamp:                 1700000000,
	}
}

// serveGetChainMetadata is a minimal in-process RPC-over-P2P "responder" for get_chain_metadata:
// it performs the responder side of protocol negotiation (supporting only
// rpc.BlockSyncProtocolID), the responder side of the RPC session handshake (always accepting),
// and then responds to exactly one method=5 RpcRequest with a canonical-framed RpcResponse
// wrapping metadata.
func serveGetChainMetadata(t *testing.T, session *p2p.Session, metadata *pb.ChainMetadata) error {
	t.Helper()

	if _, err := rpc.NegotiateProtocolInbound(session, [][]byte{rpc.BlockSyncProtocolID}); err != nil {
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

	resp := &pb.RpcResponse{RequestId: req.GetRequestId(), Status: 0}
	if metadata != nil {
		payload, err := googleproto.Marshal(metadata)
		if err != nil {
			return err
		}
		resp.Payload = payload
	}
	respBytes, err := googleproto.Marshal(resp)
	if err != nil {
		return err
	}
	return session.SendFrame(rpc.EncodeCanonicalFrame(respBytes))
}

func TestGetChainMetadataHappyPath(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	want := fixtureChainMetadata()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- serveGetChainMetadata(t, server, want)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := rpc.GetChainMetadata(ctx, client)
	if err != nil {
		t.Fatalf("GetChainMetadata: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("in-process responder failed: %v", err)
	}

	if got.GetBestBlockHeight() != want.GetBestBlockHeight() {
		t.Errorf("BestBlockHeight = %d, want %d", got.GetBestBlockHeight(), want.GetBestBlockHeight())
	}
	if !bytes.Equal(got.GetBestBlockHash(), want.GetBestBlockHash()) {
		t.Errorf("BestBlockHash = %x, want %x", got.GetBestBlockHash(), want.GetBestBlockHash())
	}
	if !bytes.Equal(got.GetAccumulatedDifficultyLow(), want.GetAccumulatedDifficultyLow()) {
		t.Errorf("AccumulatedDifficultyLow = %x, want %x", got.GetAccumulatedDifficultyLow(), want.GetAccumulatedDifficultyLow())
	}
	if !bytes.Equal(got.GetAccumulatedDifficultyHigh(), want.GetAccumulatedDifficultyHigh()) {
		t.Errorf("AccumulatedDifficultyHigh = %x, want %x", got.GetAccumulatedDifficultyHigh(), want.GetAccumulatedDifficultyHigh())
	}
	if got.GetPrunedHeight() != want.GetPrunedHeight() {
		t.Errorf("PrunedHeight = %d, want %d", got.GetPrunedHeight(), want.GetPrunedHeight())
	}
	if got.GetTimestamp() != want.GetTimestamp() {
		t.Errorf("Timestamp = %d, want %d", got.GetTimestamp(), want.GetTimestamp())
	}
}

// TestGetChainMetadataProtocolNotSupported covers the negotiation NOT_SUPPORTED path: a
// responder that doesn't support t/blksync/1 must cause the client to surface a clean,
// distinguishable error (errors.Is ErrProtocolNotSupported), not a panic.
func TestGetChainMetadataProtocolNotSupported(t *testing.T) {
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

	_, err := rpc.GetChainMetadata(ctx, client)
	if err == nil {
		t.Fatalf("expected GetChainMetadata to fail when the peer doesn't support t/blksync/1")
	}
	if !errors.Is(err, rpc.ErrProtocolNotSupported) {
		t.Fatalf("expected errors.Is(err, rpc.ErrProtocolNotSupported), got: %v", err)
	}
	<-serverErrCh // drain; the responder side is also expected to report an error, not panic
}

// TestGetChainMetadataSessionRejected covers the RPC-handshake-rejected path: a responder that
// rejects the RPC session handshake must cause the client to surface a clean, typed error
// exposing the reject reason, not a panic.
func TestGetChainMetadataSessionRejected(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	const wantReason = pb.RpcSessionReply_HANDSHAKE_REJECT_REASON_NO_SERVER_SESSIONS_AVAILABLE

	serverErrCh := make(chan error, 1)
	go func() {
		if _, err := rpc.NegotiateProtocolInbound(server, [][]byte{rpc.BlockSyncProtocolID}); err != nil {
			serverErrCh <- err
			return
		}
		serverErrCh <- rpc.RejectSessionHandshakeResponder(server, wantReason)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, err := rpc.GetChainMetadata(ctx, client)
	if err == nil {
		t.Fatalf("expected GetChainMetadata to fail when the peer rejects the RPC session handshake")
	}
	var rejected *rpc.HandshakeRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("expected a *rpc.HandshakeRejectedError, got: %v", err)
	}
	if rejected.Reason != wantReason {
		t.Fatalf("HandshakeRejectedError.Reason = %v, want %v", rejected.Reason, wantReason)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("in-process responder failed: %v", err)
	}
}

// TestGetChainMetadataNonZeroStatus covers the RpcResponse.status != 0 path: the client must
// surface a clean, typed error exposing the raw status, not attempt to decode the payload as
// ChainMetadata.
func TestGetChainMetadataNonZeroStatus(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	const wantStatus uint32 = 7

	serverErrCh := make(chan error, 1)
	go func() {
		if _, err := rpc.NegotiateProtocolInbound(server, [][]byte{rpc.BlockSyncProtocolID}); err != nil {
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

	_, err := rpc.GetChainMetadata(ctx, client)
	if err == nil {
		t.Fatalf("expected GetChainMetadata to fail on a non-zero RpcResponse.status")
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
