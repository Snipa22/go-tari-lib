package proto

import (
	"bytes"
	"testing"

	googleproto "google.golang.org/protobuf/proto"
)

// TestGetPeersRequestRoundTrip exercises a basic marshal/unmarshal round trip for the new
// GetPeersRequest message vendored in p2p/proto/dht_rpc.proto, following the same
// round-trip-style verification used elsewhere in this repo for other vendored proto types.
func TestGetPeersRequestRoundTrip(t *testing.T) {
	want := &GetPeersRequest{
		N:                    50,
		IncludeClients:       true,
		MaxClaims:            10,
		MaxAddressesPerClaim: 5,
	}

	data, err := googleproto.Marshal(want)
	if err != nil {
		t.Fatalf("marshalling GetPeersRequest: %v", err)
	}

	got := &GetPeersRequest{}
	if err := googleproto.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshalling GetPeersRequest: %v", err)
	}

	if got.GetN() != want.GetN() {
		t.Errorf("N = %d, want %d", got.GetN(), want.GetN())
	}
	if got.GetIncludeClients() != want.GetIncludeClients() {
		t.Errorf("IncludeClients = %v, want %v", got.GetIncludeClients(), want.GetIncludeClients())
	}
	if got.GetMaxClaims() != want.GetMaxClaims() {
		t.Errorf("MaxClaims = %d, want %d", got.GetMaxClaims(), want.GetMaxClaims())
	}
	if got.GetMaxAddressesPerClaim() != want.GetMaxAddressesPerClaim() {
		t.Errorf("MaxAddressesPerClaim = %d, want %d", got.GetMaxAddressesPerClaim(), want.GetMaxAddressesPerClaim())
	}
}

// fixturePeerInfo builds a fully-populated PeerInfo (including a nested PeerIdentityClaim
// carrying the reused tari.comms.identity.IdentitySignature type -- see dht_rpc.proto's doc
// comment for why this Go port reuses that existing generated type instead of vendoring a
// byte-identical duplicate) used by TestGetPeersResponseRoundTrip and
// TestPeerInfoRoundTripWithMultipleClaims below.
func fixturePeerInfo() *PeerInfo {
	return &PeerInfo{
		PublicKey: []byte{0x01, 0x02, 0x03, 0x04},
		Claims: []*PeerIdentityClaim{
			{
				Addresses:    [][]byte{[]byte("/ip4/127.0.0.1/tcp/18189")},
				PeerFeatures: 7,
				IdentitySignature: &IdentitySignature{
					Version:     1,
					Signature:   []byte{0xAA, 0xBB},
					PublicNonce: []byte{0xCC, 0xDD},
					UpdatedAt:   1700000000,
				},
			},
		},
	}
}

// TestGetPeersResponseRoundTrip exercises a marshal/unmarshal round trip for GetPeersResponse
// wrapping a PeerInfo with a single PeerIdentityClaim.
func TestGetPeersResponseRoundTrip(t *testing.T) {
	want := &GetPeersResponse{Peer: fixturePeerInfo()}

	data, err := googleproto.Marshal(want)
	if err != nil {
		t.Fatalf("marshalling GetPeersResponse: %v", err)
	}

	got := &GetPeersResponse{}
	if err := googleproto.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshalling GetPeersResponse: %v", err)
	}

	wantPeer := want.GetPeer()
	gotPeer := got.GetPeer()
	if gotPeer == nil {
		t.Fatalf("GetPeersResponse.Peer is nil after round trip")
	}
	if !bytes.Equal(gotPeer.GetPublicKey(), wantPeer.GetPublicKey()) {
		t.Errorf("PublicKey = %x, want %x", gotPeer.GetPublicKey(), wantPeer.GetPublicKey())
	}
	if len(gotPeer.GetClaims()) != len(wantPeer.GetClaims()) {
		t.Fatalf("len(Claims) = %d, want %d", len(gotPeer.GetClaims()), len(wantPeer.GetClaims()))
	}

	wantClaim := wantPeer.GetClaims()[0]
	gotClaim := gotPeer.GetClaims()[0]
	if len(gotClaim.GetAddresses()) != 1 || !bytes.Equal(gotClaim.GetAddresses()[0], wantClaim.GetAddresses()[0]) {
		t.Errorf("Addresses = %v, want %v", gotClaim.GetAddresses(), wantClaim.GetAddresses())
	}
	if gotClaim.GetPeerFeatures() != wantClaim.GetPeerFeatures() {
		t.Errorf("PeerFeatures = %d, want %d", gotClaim.GetPeerFeatures(), wantClaim.GetPeerFeatures())
	}

	wantSig := wantClaim.GetIdentitySignature()
	gotSig := gotClaim.GetIdentitySignature()
	if gotSig == nil {
		t.Fatalf("PeerIdentityClaim.IdentitySignature is nil after round trip")
	}
	if gotSig.GetVersion() != wantSig.GetVersion() {
		t.Errorf("IdentitySignature.Version = %d, want %d", gotSig.GetVersion(), wantSig.GetVersion())
	}
	if !bytes.Equal(gotSig.GetSignature(), wantSig.GetSignature()) {
		t.Errorf("IdentitySignature.Signature = %x, want %x", gotSig.GetSignature(), wantSig.GetSignature())
	}
	if !bytes.Equal(gotSig.GetPublicNonce(), wantSig.GetPublicNonce()) {
		t.Errorf("IdentitySignature.PublicNonce = %x, want %x", gotSig.GetPublicNonce(), wantSig.GetPublicNonce())
	}
	if gotSig.GetUpdatedAt() != wantSig.GetUpdatedAt() {
		t.Errorf("IdentitySignature.UpdatedAt = %d, want %d", gotSig.GetUpdatedAt(), wantSig.GetUpdatedAt())
	}
}

// TestPeerInfoRoundTripWithMultipleClaims exercises PeerInfo/PeerIdentityClaim directly (rather
// than nested inside a GetPeersResponse) with more than one claim and more than one address per
// claim, to cover the `repeated` fields more thoroughly than the single-claim/single-address
// fixture above.
func TestPeerInfoRoundTripWithMultipleClaims(t *testing.T) {
	want := &PeerInfo{
		PublicKey: []byte{0xFF},
		Claims: []*PeerIdentityClaim{
			{
				Addresses:    [][]byte{[]byte("/ip4/10.0.0.1/tcp/18189"), []byte("/ip4/10.0.0.2/tcp/18189")},
				PeerFeatures: 1,
				IdentitySignature: &IdentitySignature{
					Version:     0,
					Signature:   []byte{0x01},
					PublicNonce: []byte{0x02},
					UpdatedAt:   1,
				},
			},
			{
				Addresses:    [][]byte{[]byte("/onion3/abcdefghijklmnop:18189")},
				PeerFeatures: 2,
				IdentitySignature: &IdentitySignature{
					Version:     0,
					Signature:   []byte{0x03},
					PublicNonce: []byte{0x04},
					UpdatedAt:   2,
				},
			},
		},
	}

	data, err := googleproto.Marshal(want)
	if err != nil {
		t.Fatalf("marshalling PeerInfo: %v", err)
	}

	got := &PeerInfo{}
	if err := googleproto.Unmarshal(data, got); err != nil {
		t.Fatalf("unmarshalling PeerInfo: %v", err)
	}

	if len(got.GetClaims()) != 2 {
		t.Fatalf("len(Claims) = %d, want 2", len(got.GetClaims()))
	}
	for i, wantClaim := range want.GetClaims() {
		gotClaim := got.GetClaims()[i]
		if len(gotClaim.GetAddresses()) != len(wantClaim.GetAddresses()) {
			t.Errorf("claim %d: len(Addresses) = %d, want %d", i, len(gotClaim.GetAddresses()), len(wantClaim.GetAddresses()))
			continue
		}
		for j, addr := range wantClaim.GetAddresses() {
			if !bytes.Equal(gotClaim.GetAddresses()[j], addr) {
				t.Errorf("claim %d address %d = %q, want %q", i, j, gotClaim.GetAddresses()[j], addr)
			}
		}
		if gotClaim.GetPeerFeatures() != wantClaim.GetPeerFeatures() {
			t.Errorf("claim %d: PeerFeatures = %d, want %d", i, gotClaim.GetPeerFeatures(), wantClaim.GetPeerFeatures())
		}
	}
}
