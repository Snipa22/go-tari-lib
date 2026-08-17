package p2p

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	"github.com/Snipa22/go-tari-lib/p2p/rpc"
	googleproto "google.golang.org/protobuf/proto"
)

// quietYamuxConfig returns yamux.DefaultConfig() with LogOutput redirected to io.Discard --
// yamux logs (to stderr, by default) whenever its background recv loop's Read call on the
// underlying transport errors, which happens routinely and expectedly here once the test's
// net.Pipe()-backed Session is torn down at the end of the test; that's expected test cleanup
// noise, not a real failure, so it's silenced rather than left to clutter `go test -v` output.
func quietYamuxConfig() *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.LogOutput = io.Discard
	return cfg
}

// TestGetChainMetadataOverRealYamuxSubstream is the "did we actually wire this up right" test
// this bug fix exists for. p2p/rpc/rpc_test.go's TestGetChainMetadataHappyPath talks this
// package's negotiation/RPC-session-handshake/get_chain_metadata protocol directly over the raw
// Noise session (*p2p.Session.SendFrame/ReceiveFrame) -- that is exactly the layering bug this
// fix corrects, and it is why that test alone did not catch the real-node failure ("rpc:
// negotiation frame declares protocol id length 0 but 229 bytes follow the header").
//
// This test instead inserts a REAL github.com/hashicorp/yamux Client/Server session on top of a
// net.Pipe()-backed Noise Session pair (via sessionReadWriteCloser), opens/accepts one real
// Yamux substream, and only then runs protocol negotiation + the RPC session handshake +
// get_chain_metadata over that substream (via rpc.NewStreamTransport wrapping the substream) --
// mirroring exactly the layering p2p.ProbeChainMetadata now uses against a real node
// (Noise Session -> sessionReadWriteCloser -> yamux.Client/Open -> rpc.NewStreamTransport ->
// rpc.GetChainMetadata).
//
// This lives in package p2p (rather than p2p/rpc's own test packages) specifically so it can
// reuse the unexported sessionReadWriteCloser/newSessionReadWriteCloser adapter directly; package
// p2p already depends on package rpc in non-test code (p2p/chainmetadata_probe.go), so this
// import direction introduces no cycle.
//
// IMPORTANT CAVEAT (see p2p/VERIFICATION.md's dated section on this fix): this test proves
// internal Yamux-wiring self-consistency -- this package's own client code path and this
// package's own fake in-process responder agree with each other end to end through a real Yamux
// multiplexing layer. It CANNOT prove wire-compatibility with the real Rust `yamux` crate used
// by actual Tari nodes, since both ends of this test are this Go implementation, not a real Tari
// peer. That requires live-node re-verification, which is out of scope for this sandbox.
func TestGetChainMetadataOverRealYamuxSubstream(t *testing.T) {
	clientSession, serverSession := yamuxAdapterTestSessions(t)
	defer clientSession.Close()
	defer serverSession.Close()

	clientAdapter := newSessionReadWriteCloser(clientSession)
	serverAdapter := newSessionReadWriteCloser(serverSession)

	clientYamux, err := yamux.Client(clientAdapter, quietYamuxConfig())
	if err != nil {
		t.Fatalf("yamux.Client: %v", err)
	}
	defer clientYamux.Close()

	serverYamux, err := yamux.Server(serverAdapter, quietYamuxConfig())
	if err != nil {
		t.Fatalf("yamux.Server: %v", err)
	}
	defer serverYamux.Close()

	want := &pb.ChainMetadata{
		BestBlockHeight:           123456,
		BestBlockHash:             []byte{0x01, 0x02, 0x03, 0x04},
		AccumulatedDifficultyLow:  []byte{0xAA, 0xBB},
		AccumulatedDifficultyHigh: []byte{0xCC, 0xDD},
		PrunedHeight:              100,
		Timestamp:                 1700000000,
	}

	serverErrCh := make(chan error, 1)
	go func() {
		stream, err := serverYamux.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer stream.Close()
		serverErrCh <- serveGetChainMetadataOverStream(rpc.NewStreamTransport(stream), want)
	}()

	clientStream, err := clientYamux.Open()
	if err != nil {
		t.Fatalf("clientYamux.Open: %v", err)
	}
	defer clientStream.Close()

	clientTransport := rpc.NewStreamTransport(clientStream)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := rpc.GetChainMetadata(ctx, clientTransport)
	if err != nil {
		t.Fatalf("GetChainMetadata over real yamux substream: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("in-process fake responder failed: %v", err)
	}

	if got.GetBestBlockHeight() != want.GetBestBlockHeight() {
		t.Errorf("BestBlockHeight = %d, want %d", got.GetBestBlockHeight(), want.GetBestBlockHeight())
	}
	if got.GetPrunedHeight() != want.GetPrunedHeight() {
		t.Errorf("PrunedHeight = %d, want %d", got.GetPrunedHeight(), want.GetPrunedHeight())
	}
	if got.GetTimestamp() != want.GetTimestamp() {
		t.Errorf("Timestamp = %d, want %d", got.GetTimestamp(), want.GetTimestamp())
	}
}

// serveGetChainMetadataOverStream mirrors p2p/rpc/rpc_test.go's serveGetChainMetadata (the
// package's own fake in-process RPC-over-P2P responder for get_chain_metadata), but operates on
// an arbitrary rpc.Transport -- here, a real Yamux substream wrapped by rpc.NewStreamTransport --
// rather than directly on a *p2p.Session, since there is no *p2p.Session available once traffic
// has moved onto a Yamux substream.
//
// Unlike the outbound client path (rpc.GetChainMetadata, which calls rpc.BeginCanonicalFraming
// internally right after NegotiateProtocol succeeds), this responder drives
// NegotiateProtocolInbound/PerformSessionHandshakeResponder/the raw request-response frames
// itself, so it must call rpc.BeginCanonicalFraming itself too, at the equivalent point in its
// own sequence -- right after negotiation succeeds and before the RPC session handshake -- so
// that transport.ReceiveFrame's subsequent calls parse canonical frames rather than negotiation
// frames. See streamtransport.go's doc comments for why this signal exists at all.
func serveGetChainMetadataOverStream(transport rpc.Transport, metadata *pb.ChainMetadata) error {
	if _, err := rpc.NegotiateProtocolInbound(transport, [][]byte{rpc.BlockSyncProtocolID}); err != nil {
		return err
	}
	rpc.BeginCanonicalFraming(transport)

	if err := rpc.PerformSessionHandshakeResponder(transport); err != nil {
		return err
	}

	inFrame, err := transport.ReceiveFrame()
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
	payload, err := googleproto.Marshal(metadata)
	if err != nil {
		return err
	}
	resp.Payload = payload
	respBytes, err := googleproto.Marshal(resp)
	if err != nil {
		return err
	}
	return transport.SendFrame(rpc.EncodeCanonicalFrame(respBytes))
}
