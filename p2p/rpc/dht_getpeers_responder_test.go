package rpc_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	"github.com/Snipa22/go-tari-lib/p2p/rpc"
)

// TestServeGetPeersHappyPath covers the responder happy path: the client requests N peers via
// rpc.GetPeers, and rpc.ServeGetPeers -- fed the exact fixturePeerInfos() list -- serves back
// that whole (already-within-bounds) list, FIN-flagged, and rpc.GetPeers on the other end
// decodes exactly that list.
func TestServeGetPeersHappyPath(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	want := fixturePeerInfos()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- rpc.ServeGetPeers(server, want)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := rpc.GetPeers(ctx, client, fixtureGetPeersRequest())
	if err != nil {
		t.Fatalf("GetPeers: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("ServeGetPeers failed: %v", err)
	}

	assertPeersEqual(t, got, want)
}

// TestServeGetPeersEmptyList covers the responder's zero-peer case: ServeGetPeers must still
// send a single, FIN-flagged, empty-payload RpcResponse rather than hanging or erroring, and the
// client must come back with an empty (not nil-panicking) slice.
func TestServeGetPeersEmptyList(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- rpc.ServeGetPeers(server, nil)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := rpc.GetPeers(ctx, client, fixtureGetPeersRequest())
	if err != nil {
		t.Fatalf("GetPeers: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("ServeGetPeers failed: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 peers back, got %d", len(got))
	}
}

// TestServeGetPeersEnforcesNBoundServerSide covers the core "never trust the caller" requirement:
// ServeGetPeers is handed MORE peers than the request's own N, and must truncate to exactly N
// server-side rather than sending the caller's full (over-large) list.
func TestServeGetPeersEnforcesNBoundServerSide(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	allPeers := fixturePeerInfos() // 3 peers
	const requestedN = 2

	serverErrCh := make(chan error, 1)
	go func() {
		// ServeGetPeers is handed all 3 peers, even though the client below will ask for only
		// requestedN=2 -- it must truncate itself, not trust that the caller already did.
		serverErrCh <- rpc.ServeGetPeers(server, allPeers)
	}()

	req := fixtureGetPeersRequest()
	req.N = requestedN

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := rpc.GetPeers(ctx, client, req)
	if err != nil {
		t.Fatalf("GetPeers: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("ServeGetPeers failed: %v", err)
	}

	if len(got) != requestedN {
		t.Fatalf("len(peers) = %d, want %d (server-side N bound not enforced)", len(got), requestedN)
	}
	assertPeersEqual(t, got, allPeers[:requestedN])
}

// TestServeGetPeersEnforcesMaxClaimsAndMaxAddressesBoundServerSide covers the per-peer/
// per-claim bounds: ServeGetPeers is handed a peer with more claims than MaxClaims, and a claim
// with more addresses than MaxAddressesPerClaim, and must truncate both server-side.
func TestServeGetPeersEnforcesMaxClaimsAndMaxAddressesBoundServerSide(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	overLargePeer := &pb.PeerInfo{
		PublicKey: []byte{0xAA},
		Claims: []*pb.PeerIdentityClaim{
			{Addresses: [][]byte{[]byte("/ip4/10.0.0.1/tcp/1"), []byte("/ip4/10.0.0.1/tcp/2"), []byte("/ip4/10.0.0.1/tcp/3")}, PeerFeatures: 1},
			{Addresses: [][]byte{[]byte("/ip4/10.0.0.2/tcp/1")}, PeerFeatures: 2},
			{Addresses: [][]byte{[]byte("/ip4/10.0.0.3/tcp/1")}, PeerFeatures: 3},
		},
	}

	const maxClaims = 2
	const maxAddressesPerClaim = 1

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- rpc.ServeGetPeers(server, []*pb.PeerInfo{overLargePeer})
	}()

	req := fixtureGetPeersRequest()
	req.N = 0 // no count bound requested -- exercises MaxClaims/MaxAddressesPerClaim independently
	req.MaxClaims = maxClaims
	req.MaxAddressesPerClaim = maxAddressesPerClaim

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := rpc.GetPeers(ctx, client, req)
	if err != nil {
		t.Fatalf("GetPeers: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("ServeGetPeers failed: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("len(peers) = %d, want 1", len(got))
	}
	if len(got[0].GetClaims()) != maxClaims {
		t.Fatalf("len(Claims) = %d, want %d (MaxClaims bound not enforced server-side)", len(got[0].GetClaims()), maxClaims)
	}
	for i, claim := range got[0].GetClaims() {
		if len(claim.GetAddresses()) != maxAddressesPerClaim {
			t.Fatalf("claim %d: len(Addresses) = %d, want %d (MaxAddressesPerClaim bound not enforced server-side)",
				i, len(claim.GetAddresses()), maxAddressesPerClaim)
		}
	}
	// The original, over-large peer handed to ServeGetPeers must not have been mutated.
	if len(overLargePeer.GetClaims()) != 3 {
		t.Fatalf("ServeGetPeers mutated the caller-supplied peer's Claims slice: len = %d, want 3", len(overLargePeer.GetClaims()))
	}
	if len(overLargePeer.GetClaims()[0].GetAddresses()) != 3 {
		t.Fatalf("ServeGetPeers mutated the caller-supplied peer's claim Addresses slice: len = %d, want 3",
			len(overLargePeer.GetClaims()[0].GetAddresses()))
	}
}

// TestServeGetPeersProtocolNotSupported covers the NOT_SUPPORTED substream-negotiation path from
// the RESPONDER's own point of view: if the "client" side negotiates some other protocol against
// ServeGetPeers (which only ever offers t/dht/1), ServeGetPeers must return an error wrapping
// rpc.ErrProtocolNotSupported and must not attempt to read/serve a request at all.
func TestServeGetPeersProtocolNotSupported(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- rpc.ServeGetPeers(server, fixturePeerInfos())
	}()

	clientErrCh := make(chan error, 1)
	go func() {
		clientErrCh <- rpc.NegotiateProtocol(client, []byte("t/some-other-protocol/1"))
	}()

	if err := <-clientErrCh; err == nil {
		t.Fatalf("expected the client's NegotiateProtocol to fail (server only supports t/dht/1)")
	} else if !errors.Is(err, rpc.ErrProtocolNotSupported) {
		t.Fatalf("expected errors.Is(err, rpc.ErrProtocolNotSupported), got: %v", err)
	}

	err := <-serverErrCh
	if err == nil {
		t.Fatalf("expected ServeGetPeers to fail when the peer requests an unsupported protocol")
	}
	if !errors.Is(err, rpc.ErrProtocolNotSupported) {
		t.Fatalf("expected errors.Is(err, rpc.ErrProtocolNotSupported), got: %v", err)
	}
}

// TestServeGetPeersPublicKeysPreserved is a light sanity check that public keys round-trip
// byte-exact through ServeGetPeers's bounding/copying logic.
func TestServeGetPeersPublicKeysPreserved(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	want := fixturePeerInfos()

	serverErrCh := make(chan error, 1)
	go func() {
		serverErrCh <- rpc.ServeGetPeers(server, want)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	got, err := rpc.GetPeers(ctx, client, fixtureGetPeersRequest())
	if err != nil {
		t.Fatalf("GetPeers: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("ServeGetPeers failed: %v", err)
	}
	for i := range want {
		if !bytes.Equal(got[i].GetPublicKey(), want[i].GetPublicKey()) {
			t.Errorf("peer %d: PublicKey = %x, want %x", i, got[i].GetPublicKey(), want[i].GetPublicKey())
		}
	}
}
