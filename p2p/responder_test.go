package p2p_test

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-lib/p2p"
	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	rpcpkg "github.com/Snipa22/go-tari-lib/p2p/rpc"
)

// fixtureResponderPeerInfos returns the peer list p2p.Serve's PeerListProvider will feed to
// every get_peers request in the tests below.
func fixtureResponderPeerInfos() []*pb.PeerInfo {
	return []*pb.PeerInfo{
		{
			PublicKey: []byte{0x11},
			Claims: []*pb.PeerIdentityClaim{
				{Addresses: [][]byte{[]byte("/ip4/10.9.0.1/tcp/18189")}, PeerFeatures: 3},
			},
		},
		{
			PublicKey: []byte{0x22},
			Claims: []*pb.PeerIdentityClaim{
				{Addresses: [][]byte{[]byte("/ip4/10.9.0.2/tcp/18189")}, PeerFeatures: 3},
			},
		},
	}
}

// startTestResponder starts p2p.Serve on a fresh loopback TCP listener with the given peer list
// and OnPeerIdentity callback, returning the listener's address and a cleanup func. Mirrors how
// cmd/p2p-responder-spike/main.go wires up p2p.Serve, just with a static peer list and t.Logf
// tracing instead of an in-memory time-windowed store and stdout.
func startTestResponder(t *testing.T, peers []*pb.PeerInfo, onIdentity func(net.Addr, []byte, *p2p.PeerInfo)) (addr string, cleanup func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting loopback listener: %v", err)
	}

	responderStatic, err := p2p.GenerateRistrettoKeypair()
	if err != nil {
		listener.Close()
		t.Fatalf("generating responder static keypair: %v", err)
	}

	cfg := p2p.ResponderConfig{
		StaticKeypair: responderStatic,
		OurFeatures:   p2p.FeaturesCommunicationNode,
		PeerListProvider: func() []*pb.PeerInfo {
			return peers
		},
		OnPeerIdentity: onIdentity,
		Logf:           t.Logf,
	}

	serveCtx, serveCancel := context.WithCancel(context.Background())
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- p2p.Serve(serveCtx, listener, cfg)
	}()

	cleanup = func() {
		serveCancel()
		listener.Close()
		<-serveErrCh
	}
	return listener.Addr().String(), cleanup
}

// TestServeEndToEndOverLoopback runs p2p.Serve (BRIEF.md item 2's responder loop) on a real
// loopback TCP listener and drives a "fake client" against it using this repo's own,
// already-proven client-side code path (p2p.Probe for the handshake+identity-exchange half,
// p2p.ProbeGetPeersWithOptions for the Yamux-substream+t/dht/1-negotiation+get_peers half) --
// exactly the combination BRIEF.md's own "LIVE VERIFICATION" section reuses for the live
// loopback sanity test, just against an in-process listener instead of the real standalone
// binary. This proves the full responder loop end to end, in-process.
func TestServeEndToEndOverLoopback(t *testing.T) {
	wantPeers := fixtureResponderPeerInfos()

	type identityReport struct {
		remoteAddr net.Addr
		staticKey  []byte
		identity   *p2p.PeerInfo
	}
	identityCh := make(chan identityReport, 2)

	addr, cleanup := startTestResponder(t, wantPeers, func(remoteAddr net.Addr, staticKey []byte, identity *p2p.PeerInfo) {
		identityCh <- identityReport{remoteAddr: remoteAddr, staticKey: staticKey, identity: identity}
	})
	defer cleanup()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Half 1: plain Probe, to check the responder actually advertises COMMUNICATION_NODE
	// features (BRIEF.md point 2) and that OnPeerIdentity fires with the right static key.
	probeInfo, err := p2p.Probe(ctx, addr)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if probeInfo.Features != p2p.FeaturesCommunicationNode {
		t.Errorf("responder advertised Features = %d, want %d (FeaturesCommunicationNode)", probeInfo.Features, p2p.FeaturesCommunicationNode)
	}
	select {
	case report := <-identityCh:
		if len(report.staticKey) != 32 {
			t.Errorf("OnPeerIdentity reported a static key of %d bytes, want 32", len(report.staticKey))
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for OnPeerIdentity to fire for the Probe connection")
	}

	// Half 2: ProbeGetPeersWithOptions, exercising the Yamux substream + t/dht/1 negotiation +
	// get_peers RPC against p2p.Serve's substream-handling path.
	got, err := p2p.ProbeGetPeersWithOptions(ctx, addr, rpcpkg.GetPeersRequest{N: 50, MaxClaims: 10, MaxAddressesPerClaim: 10}, p2p.ProbeOptions{})
	if err != nil {
		t.Fatalf("ProbeGetPeersWithOptions: %v", err)
	}
	select {
	case <-identityCh:
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for OnPeerIdentity to fire for the ProbeGetPeersWithOptions connection")
	}

	if len(got) != len(wantPeers) {
		t.Fatalf("len(peers) = %d, want %d", len(got), len(wantPeers))
	}
	for i := range wantPeers {
		if !bytes.Equal(got[i].GetPublicKey(), wantPeers[i].GetPublicKey()) {
			t.Errorf("peer %d: PublicKey = %x, want %x", i, got[i].GetPublicKey(), wantPeers[i].GetPublicKey())
		}
	}
}

// TestServeEmptyPeerListProvider covers PeerListProvider == nil (Serve must serve an empty list,
// not panic).
func TestServeEmptyPeerListProvider(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting loopback listener: %v", err)
	}
	defer listener.Close()

	responderStatic, err := p2p.GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating responder static keypair: %v", err)
	}

	cfg := p2p.ResponderConfig{
		StaticKeypair: responderStatic,
		OurFeatures:   p2p.FeaturesCommunicationNode,
		Logf:          t.Logf,
	}

	serveCtx, serveCancel := context.WithCancel(context.Background())
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- p2p.Serve(serveCtx, listener, cfg)
	}()
	defer func() {
		serveCancel()
		listener.Close()
		<-serveErrCh
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := p2p.ProbeGetPeersWithOptions(ctx, listener.Addr().String(), rpcpkg.GetPeersRequest{N: 50}, p2p.ProbeOptions{})
	if err != nil {
		t.Fatalf("ProbeGetPeersWithOptions: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 peers with a nil PeerListProvider, got %d", len(got))
	}
}
