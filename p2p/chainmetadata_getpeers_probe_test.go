package p2p

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	"github.com/Snipa22/go-tari-lib/p2p/rpc"
	googleproto "google.golang.org/protobuf/proto"
)

// This file covers the new ProbeOptions-aware dial-selection code path added to
// ProbeChainMetadataWithOptions/ProbeGetPeersWithOptions (p2p/chainmetadata_probe.go,
// p2p/getpeers_probe.go), mirroring p2p/socks_test.go's test shapes/naming for the equivalent
// Probe/ProbeWithOptions coverage. It deliberately does NOT re-test the already-covered
// Yamux/RPC-over-P2P logic itself (see p2p/yamux_rpc_integration_test.go and p2p/rpc/*_test.go
// for that) beyond what's needed to prove the dial-selection change didn't break the existing
// happy path.
//
// NOTE (matching p2p/socks_test.go's own documented gap): no live Tor daemon is available in
// this sandbox, so none of the tests below exercise a real end-to-end `.onion` dial through an
// actual Tor daemon or a real onion-addressed Tari peer -- see p2p/VERIFICATION.md for the
// explicitly documented follow-up.

// TestProbeChainMetadataWithOptionsOnionWithoutProxyReturnsSpecificError mirrors
// TestDialForProbeOnionWithoutProxyReturnsSpecificError (p2p/socks_test.go): a `.onion` address
// with no SocksProxyAddr configured must surface dialForProbe's specific
// onion-requires-a-proxy error, unrewrapped into something unrecognizable, rather than a
// generic timeout/DNS error.
func TestProbeChainMetadataWithOptionsOnionWithoutProxyReturnsSpecificError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := ProbeChainMetadataWithOptions(ctx, "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:80", ProbeOptions{})
	if err == nil {
		t.Fatalf("expected an error for a .onion address with no SOCKS proxy configured")
	}
	if !strings.Contains(err.Error(), "requires a SOCKS5 proxy") {
		t.Fatalf("expected the onion-requires-proxy error to surface, got: %v", err)
	}
}

// TestProbeGetPeersWithOptionsOnionWithoutProxyReturnsSpecificError is
// TestProbeChainMetadataWithOptionsOnionWithoutProxyReturnsSpecificError's equivalent for
// ProbeGetPeersWithOptions.
func TestProbeGetPeersWithOptionsOnionWithoutProxyReturnsSpecificError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := ProbeGetPeersWithOptions(ctx, "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion:80", DefaultGetPeersRequest(), ProbeOptions{})
	if err == nil {
		t.Fatalf("expected an error for a .onion address with no SOCKS proxy configured")
	}
	if !strings.Contains(err.Error(), "requires a SOCKS5 proxy") {
		t.Fatalf("expected the onion-requires-proxy error to surface, got: %v", err)
	}
}

// fixtureChainMetadataForProbeTest is an arbitrary, fully-populated ChainMetadata used below to
// verify ProbeChainMetadataWithOptions decodes exactly what the in-process responder sent.
// Mirrors p2p/rpc/rpc_test.go's fixtureChainMetadata (duplicated here rather than exported,
// since that helper lives in an external test package, p2p/rpc_test, that this package's
// internal tests can't import without a cycle).
func fixtureChainMetadataForProbeTest() *pb.ChainMetadata {
	return &pb.ChainMetadata{
		BestBlockHeight:           654321,
		BestBlockHash:             []byte{0x0a, 0x0b, 0x0c, 0x0d},
		AccumulatedDifficultyLow:  []byte{0x11, 0x22},
		AccumulatedDifficultyHigh: []byte{0x33, 0x44},
		PrunedHeight:              200,
		Timestamp:                 1800000000,
	}
}

// runProbeChainMetadataAgainstInProcessResponder stands up a real loopback TCP listener and an
// in-process responder that speaks the full protocol ProbeChainMetadataWithOptions expects
// (Noise_XX handshake -> identity exchange -> real Yamux server session/Accept ->
// negotiation/RPC-session-handshake/get_chain_metadata over that substream, reusing
// serveGetChainMetadataOverStream from p2p/yamux_rpc_integration_test.go and quietYamuxConfig
// from the same file), then calls probe(ctx, addr) against it -- where probe is either
// ProbeChainMetadata or a closure around ProbeChainMetadataWithOptions with some ProbeOptions,
// letting callers verify both the thin-wrapper delegation and the new opts-aware dial-selection
// path against the exact same responder logic.
func runProbeChainMetadataAgainstInProcessResponder(t *testing.T, probe func(ctx context.Context, addr string) (*ChainMetadataInfo, error)) *ChainMetadataInfo {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting loopback listener: %v", err)
	}
	defer listener.Close()

	responderStatic, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating responder static keypair: %v", err)
	}

	want := fixtureChainMetadataForProbeTest()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		session, err := ResponderHandshake(ctx, conn, responderStatic)
		if err != nil {
			serverErrCh <- err
			return
		}
		defer session.Close()

		if _, err := session.ExchangeIdentity(ctx); err != nil {
			serverErrCh <- err
			return
		}

		adapter := newSessionReadWriteCloser(session)
		yamuxSession, err := yamux.Server(adapter, quietYamuxConfig())
		if err != nil {
			serverErrCh <- err
			return
		}
		defer yamuxSession.Close()

		stream, err := yamuxSession.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer stream.Close()

		serverErrCh <- serveGetChainMetadataOverStream(rpc.NewStreamTransport(stream), want)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := probe(ctx, listener.Addr().String())
	if err != nil {
		t.Fatalf("probe against in-process responder failed: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("in-process responder side failed: %v", err)
	}

	if got.BestBlockHeight != want.GetBestBlockHeight() {
		t.Errorf("BestBlockHeight = %d, want %d", got.BestBlockHeight, want.GetBestBlockHeight())
	}
	if !bytes.Equal(got.BestBlockHash, want.GetBestBlockHash()) {
		t.Errorf("BestBlockHash = %x, want %x", got.BestBlockHash, want.GetBestBlockHash())
	}
	if got.PrunedHeight != want.GetPrunedHeight() {
		t.Errorf("PrunedHeight = %d, want %d", got.PrunedHeight, want.GetPrunedHeight())
	}
	if got.Timestamp != want.GetTimestamp() {
		t.Errorf("Timestamp = %d, want %d", got.Timestamp, want.GetTimestamp())
	}
	if got.Latency <= 0 {
		t.Errorf("expected a positive Latency, got %s", got.Latency)
	}
	return got
}

// TestProbeChainMetadataZeroConfigStillWorks proves ProbeChainMetadata itself (the exported,
// pre-existing signature/behavior) still succeeds end to end now that it's a thin wrapper around
// ProbeChainMetadataWithOptions -- the "zero-config behavior MUST be byte-for-byte unchanged"
// requirement for this refactor.
func TestProbeChainMetadataZeroConfigStillWorks(t *testing.T) {
	runProbeChainMetadataAgainstInProcessResponder(t, ProbeChainMetadata)
}

// TestProbeChainMetadataWithOptionsNonOnionBypassesConfiguredProxy mirrors
// TestDialForProbeNonOnionBypassesConfiguredProxy (p2p/socks_test.go), but through the full
// ProbeChainMetadataWithOptions call rather than dialForProbe directly: a non-`.onion` address
// must still complete the full handshake/Yamux/RPC round trip successfully, both with the zero
// value of ProbeOptions and with a configured-but-bogus SocksProxyAddr (proving the proxy is
// bypassed entirely for non-onion addresses, rather than merely unset).
func TestProbeChainMetadataWithOptionsNonOnionBypassesConfiguredProxy(t *testing.T) {
	bogusListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a bogus proxy port: %v", err)
	}
	bogusProxyAddr := bogusListener.Addr().String()
	bogusListener.Close()

	cases := []struct {
		name string
		opts ProbeOptions
	}{
		{"zero value ProbeOptions", ProbeOptions{}},
		{"configured but bogus SocksProxyAddr", ProbeOptions{SocksProxyAddr: bogusProxyAddr}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runProbeChainMetadataAgainstInProcessResponder(t, func(ctx context.Context, addr string) (*ChainMetadataInfo, error) {
				return ProbeChainMetadataWithOptions(ctx, addr, c.opts)
			})
		})
	}
}

// TestProbeChainMetadataWithOptionsZeroValueMatchesProbeChainMetadata mirrors
// TestProbeWithOptionsZeroValueMatchesProbe's spirit but adapted to what's realistic without a
// full fake RPC responder for the failure path: against an unreachable address,
// ProbeChainMetadataWithOptions(ctx, addr, ProbeOptions{}) and ProbeChainMetadata(ctx, addr) must
// fail identically (ProbeChainMetadata literally delegates to the WithOptions call with a zero
// ProbeOptions, so their errors must match exactly, not just be "some error").
func TestProbeChainMetadataWithOptionsZeroValueMatchesProbeChainMetadata(t *testing.T) {
	// Reserve then immediately close a loopback port so nothing is listening there.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, wantErr := ProbeChainMetadata(ctx, addr)
	if wantErr == nil {
		t.Fatalf("expected ProbeChainMetadata against an unreachable address to return an error")
	}

	_, gotErr := ProbeChainMetadataWithOptions(ctx, addr, ProbeOptions{})
	if gotErr == nil {
		t.Fatalf("expected ProbeChainMetadataWithOptions against an unreachable address to return an error")
	}

	if gotErr.Error() != wantErr.Error() {
		t.Fatalf("ProbeChainMetadataWithOptions error = %q, want it to match ProbeChainMetadata's error %q", gotErr.Error(), wantErr.Error())
	}
}

// fixturePeerInfosForProbeTest returns 2 arbitrary, distinguishable PeerInfo fixtures used below
// to verify ProbeGetPeersWithOptions collects all streamed peers in order. Mirrors
// p2p/rpc/dht_getpeers_test.go's fixturePeerInfos (duplicated here for the same "lives in an
// external test package" reason as fixtureChainMetadataForProbeTest above).
func fixturePeerInfosForProbeTest() []*pb.PeerInfo {
	return []*pb.PeerInfo{
		{
			PublicKey: []byte{0xa1},
			Claims: []*pb.PeerIdentityClaim{
				{Addresses: [][]byte{[]byte("/ip4/10.1.0.1/tcp/18189")}, PeerFeatures: 1},
			},
		},
		{
			PublicKey: []byte{0xa2},
			Claims: []*pb.PeerIdentityClaim{
				{Addresses: [][]byte{[]byte("/ip4/10.1.0.2/tcp/18189")}, PeerFeatures: 2},
			},
		},
	}
}

// serveGetPeersStreamingOverStream is p2p/rpc/dht_getpeers_test.go's serveGetPeersStreaming,
// adapted to operate on an arbitrary rpc.Transport (here, a real Yamux substream wrapped by
// rpc.NewStreamTransport) rather than directly on a *p2p.Session -- mirroring how
// p2p/yamux_rpc_integration_test.go's serveGetChainMetadataOverStream adapts
// p2p/rpc/rpc_test.go's serveGetChainMetadata the same way. Sends each peer as a separate
// streaming RpcResponse, with the FIN flag set on the same message as the last peer's payload
// (no separate empty terminator frame).
func serveGetPeersStreamingOverStream(transport rpc.Transport, peers []*pb.PeerInfo) error {
	if _, err := rpc.NegotiateProtocolInbound(transport, [][]byte{rpc.DhtProtocolID}); err != nil {
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

	const rpcResponseFlagFIN uint32 = 0x01
	for i, peer := range peers {
		flags := uint32(0)
		if i == len(peers)-1 {
			flags = rpcResponseFlagFIN
		}
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
		if err := transport.SendFrame(rpc.EncodeCanonicalFrame(respBytes)); err != nil {
			return err
		}
	}
	return nil
}

// runProbeGetPeersAgainstInProcessResponder is
// runProbeChainMetadataAgainstInProcessResponder's equivalent for ProbeGetPeers/
// ProbeGetPeersWithOptions.
func runProbeGetPeersAgainstInProcessResponder(t *testing.T, probe func(ctx context.Context, addr string) ([]*pb.PeerInfo, error)) []*pb.PeerInfo {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting loopback listener: %v", err)
	}
	defer listener.Close()

	responderStatic, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating responder static keypair: %v", err)
	}

	want := fixturePeerInfosForProbeTest()

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		session, err := ResponderHandshake(ctx, conn, responderStatic)
		if err != nil {
			serverErrCh <- err
			return
		}
		defer session.Close()

		if _, err := session.ExchangeIdentity(ctx); err != nil {
			serverErrCh <- err
			return
		}

		adapter := newSessionReadWriteCloser(session)
		yamuxSession, err := yamux.Server(adapter, quietYamuxConfig())
		if err != nil {
			serverErrCh <- err
			return
		}
		defer yamuxSession.Close()

		stream, err := yamuxSession.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer stream.Close()

		serverErrCh <- serveGetPeersStreamingOverStream(rpc.NewStreamTransport(stream), want)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := probe(ctx, listener.Addr().String())
	if err != nil {
		t.Fatalf("probe against in-process responder failed: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("in-process responder side failed: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("len(peers) = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i].GetPublicKey(), want[i].GetPublicKey()) {
			t.Errorf("peer %d: PublicKey = %x, want %x", i, got[i].GetPublicKey(), want[i].GetPublicKey())
		}
	}
	return got
}

// TestProbeGetPeersZeroConfigStillWorks is
// TestProbeChainMetadataZeroConfigStillWorks's equivalent for ProbeGetPeers.
func TestProbeGetPeersZeroConfigStillWorks(t *testing.T) {
	runProbeGetPeersAgainstInProcessResponder(t, func(ctx context.Context, addr string) ([]*pb.PeerInfo, error) {
		return ProbeGetPeers(ctx, addr, DefaultGetPeersRequest())
	})
}

// TestProbeGetPeersWithOptionsNonOnionBypassesConfiguredProxy is
// TestProbeChainMetadataWithOptionsNonOnionBypassesConfiguredProxy's equivalent for
// ProbeGetPeersWithOptions.
func TestProbeGetPeersWithOptionsNonOnionBypassesConfiguredProxy(t *testing.T) {
	bogusListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a bogus proxy port: %v", err)
	}
	bogusProxyAddr := bogusListener.Addr().String()
	bogusListener.Close()

	cases := []struct {
		name string
		opts ProbeOptions
	}{
		{"zero value ProbeOptions", ProbeOptions{}},
		{"configured but bogus SocksProxyAddr", ProbeOptions{SocksProxyAddr: bogusProxyAddr}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			runProbeGetPeersAgainstInProcessResponder(t, func(ctx context.Context, addr string) ([]*pb.PeerInfo, error) {
				return ProbeGetPeersWithOptions(ctx, addr, DefaultGetPeersRequest(), c.opts)
			})
		})
	}
}

// TestProbeGetPeersWithOptionsZeroValueMatchesProbeGetPeers is
// TestProbeChainMetadataWithOptionsZeroValueMatchesProbeChainMetadata's equivalent for
// ProbeGetPeers/ProbeGetPeersWithOptions.
func TestProbeGetPeersWithOptionsZeroValueMatchesProbeGetPeers(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	req := DefaultGetPeersRequest()

	_, wantErr := ProbeGetPeers(ctx, addr, req)
	if wantErr == nil {
		t.Fatalf("expected ProbeGetPeers against an unreachable address to return an error")
	}

	_, gotErr := ProbeGetPeersWithOptions(ctx, addr, req, ProbeOptions{})
	if gotErr == nil {
		t.Fatalf("expected ProbeGetPeersWithOptions against an unreachable address to return an error")
	}

	if gotErr.Error() != wantErr.Error() {
		t.Fatalf("ProbeGetPeersWithOptions error = %q, want it to match ProbeGetPeers's error %q", gotErr.Error(), wantErr.Error())
	}
}
