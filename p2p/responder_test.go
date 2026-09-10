package p2p_test

import (
	"bytes"
	"context"
	"errors"
	"net"
	"sync/atomic"
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
		PeerListProvider: func(ctx context.Context) ([]*pb.PeerInfo, error) {
			return peers, nil
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

// TestServeAdvertisesConfiguredAddressesWithValidSignature is BRIEF2.md's "Finish the
// advertising" integration test (point 2): starts a responder configured with a fake
// /ip4/1.2.3.4/tcp/18189 address (ResponderConfig.OurAddresses, exactly as
// cmd/p2p-responder-spike/main.go's -public-tcp-addr flag would wire it up -- see
// parseAdvertisedAddresses there and p2p.EncodeMultiaddrString), dials it with a probing client,
// and confirms:
//
//  1. The received PeerInfo.Addresses matches the configured address, in its real raw-binary
//     rust-multiaddr wire encoding (p2p.EncodeMultiaddrString) -- NOT the address's UTF-8 string
//     form.
//  2. The received identity's IdentitySignature is cryptographically valid for the ACTUAL
//     claimed features/addresses (via p2p.VerifyIdentitySignature, the same real
//     Tari-equivalent Schnorr verification this repo's identity_signature_test.go tests exercise
//     directly) -- proving BRIEF2.md's THE BUG fix actually reaches a live end-to-end exchange,
//     not just the lower-level buildOurIdentitySignature unit tests.
func TestServeAdvertisesConfiguredAddressesWithValidSignature(t *testing.T) {
	wantAddr, err := p2p.EncodeMultiaddrString("/ip4/1.2.3.4/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString: %v", err)
	}

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
		OurAddresses:  [][]byte{wantAddr},
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

	probeInfo, err := p2p.Probe(ctx, listener.Addr().String())
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}

	if probeInfo.Features != p2p.FeaturesCommunicationNode {
		t.Errorf("responder advertised Features = %d, want %d (FeaturesCommunicationNode)", probeInfo.Features, p2p.FeaturesCommunicationNode)
	}
	if len(probeInfo.Addresses) != 1 || !bytes.Equal(probeInfo.Addresses[0], wantAddr) {
		t.Fatalf("responder advertised Addresses = %x, want [%x]", probeInfo.Addresses, wantAddr)
	}

	if probeInfo.IdentitySignature == nil {
		t.Fatalf("responder sent no identity_signature")
	}
	valid, err := p2p.VerifyIdentitySignature(probeInfo.RemoteStaticPubKey, probeInfo.Features, probeInfo.Addresses, probeInfo.IdentitySignature)
	if err != nil {
		t.Fatalf("VerifyIdentitySignature: %v", err)
	}
	if !valid {
		t.Fatalf("responder's identity_signature does not verify against its own claimed features=%d/addresses=%x -- this is exactly what a real Tari peer's validate_peer_identity_message checks and would reject the connection over", probeInfo.Features, probeInfo.Addresses)
	}

	// Sanity check the fix actually matters: verification against a DIFFERENT claimed features/
	// addresses (e.g. what the old hardcoded-features=0/no-addresses bug would have signed
	// instead) must fail.
	tamperedValid, err := p2p.VerifyIdentitySignature(probeInfo.RemoteStaticPubKey, 0, nil, probeInfo.IdentitySignature)
	if err != nil {
		t.Fatalf("VerifyIdentitySignature (tampered claim): %v", err)
	}
	if tamperedValid {
		t.Fatalf("responder's identity_signature incorrectly verified against features=0/no addresses (the pre-fix hardcoded claim)")
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

// TestServePeerListProviderErrorServesEmptyList covers PeerListProvider's error-handling
// contract (see its doc comment): a PeerListProvider that returns a non-nil error -- exactly
// what a real, DB-backed implementation does on a transient failure/timeout -- must degrade to
// an EMPTY served peer list rather than crashing the substream/connection or propagating the
// error to the get_peers client in any way ProbeGetPeersWithOptions would surface as a failure.
func TestServePeerListProviderErrorServesEmptyList(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting loopback listener: %v", err)
	}
	defer listener.Close()

	responderStatic, err := p2p.GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating responder static keypair: %v", err)
	}

	providerErr := errors.New("simulated transient DB failure")
	var providerCalled int32

	cfg := p2p.ResponderConfig{
		StaticKeypair: responderStatic,
		OurFeatures:   p2p.FeaturesCommunicationNode,
		PeerListProvider: func(ctx context.Context) ([]*pb.PeerInfo, error) {
			atomic.AddInt32(&providerCalled, 1)
			if ctx == nil {
				t.Errorf("PeerListProvider called with a nil context.Context")
			}
			return fixtureResponderPeerInfos(), providerErr
		},
		Logf: t.Logf,
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
		t.Fatalf("ProbeGetPeersWithOptions: %v (a PeerListProvider error must degrade to an empty list, not a client-visible failure)", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 peers when PeerListProvider returns an error (even though it also returned a non-empty list alongside the error, which must be discarded), got %d", len(got))
	}
	if atomic.LoadInt32(&providerCalled) == 0 {
		t.Fatalf("PeerListProvider was never called")
	}
}
