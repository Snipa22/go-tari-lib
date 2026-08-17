package p2p

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/flynn/noise"
	"github.com/gtank/ristretto255"

	identitypb "github.com/Snipa22/go-tari-lib/p2p/proto"
)

// identitySignatureVersion is `IdentitySignature::LATEST_VERSION` (source:
// tari/comms/core/src/peer_manager/identity_signature.rs): a single u8, currently 0. Both the
// wire IdentitySignature.version field (a u32 in the protobuf schema, but only ever populated
// with this u8 value) and the version byte fed into the challenge hash below use this same
// constant.
const identitySignatureVersion = 0

// buildOurIdentitySignature computes a real Ristretto255 Schnorr IdentitySignature over our own
// outgoing PeerIdentityMsg fields, signed with staticKeypair -- the SAME long-term keypair used
// for the Noise_XX handshake (source: tari/comms/core/src/peer_manager/identity_signature.rs,
// `IdentitySignature::sign_new`/`construct_challenge`, and tari-crypto/src/signatures/schnorr.rs,
// `sign_raw_uniform`).
//
// Real Tari nodes validate this on every inbound connection (source:
// tari/comms/core/src/connection_manager/common.rs, `validate_peer_identity_message`) and reject
// a PeerIdentityMsg with no IdentitySignature at all (`PeerManagerError::
// MissingIdentitySignature`) by closing the connection -- so sending a real signature here is
// required for interop with any real Tari node, not an optional enhancement.
//
// This only covers the fields this client's outgoing PeerIdentityMsg actually sets
// (ourPeerIdentityMsgBytes, identity.go): features=0, no addresses. The challenge construction
// below deliberately omits the per-address chain step Rust's construct_challenge performs for
// each claimed address, since we claim none -- that step is a documented no-op for us, not a
// missing feature.
func buildOurIdentitySignature(staticKeypair noise.DHKey) (*identitypb.IdentitySignature, error) {
	secretKey, err := ristretto255.NewScalar().SetCanonicalBytes(staticKeypair.Private)
	if err != nil {
		return nil, fmt.Errorf("p2p: decoding our own static private key as a ristretto255 scalar: %w", err)
	}

	// Fresh signature nonce: a uniformly random scalar and its public point R = nonce*G.
	// GenerateRistrettoKeypair already implements exactly this (see ristretto_dh.go) -- reused
	// here rather than duplicating the "64 random bytes -> SetUniformBytes -> ScalarBaseMult"
	// construction a second time.
	nonceKeypair, err := GenerateRistrettoKeypair()
	if err != nil {
		return nil, fmt.Errorf("p2p: generating identity signature nonce: %w", err)
	}
	secretNonce, err := ristretto255.NewScalar().SetCanonicalBytes(nonceKeypair.Private)
	if err != nil {
		return nil, fmt.Errorf("p2p: decoding identity signature nonce as a ristretto255 scalar: %w", err)
	}

	updatedAt := time.Now().Unix()

	// e = H(P||R||version||updated_at||features||addresses...) -- see construct_challenge
	// (identity_signature.rs). We send no addresses, so that chain step is omitted (see doc
	// comment above). Each .Chain call below is this package's own byte-exact-verified
	// length-prefixed Chain() semantics (hashing.go) -- no extra wrapping is added here.
	var updatedAtBuf [8]byte
	binary.LittleEndian.PutUint64(updatedAtBuf[:], uint64(updatedAt))

	var featuresBuf [4]byte
	binary.LittleEndian.PutUint32(featuresBuf[:], 0) // features=0, matches PeerIdentityMsg.Features

	challenge := newCommsCorePeerManagerHasher512(identitySignatureLabel).
		Chain(staticKeypair.Public).
		Chain(nonceKeypair.Public).
		Chain([]byte{identitySignatureVersion}).
		Chain(updatedAtBuf[:]).
		Chain(featuresBuf[:]).
		Finalize()

	// e = Scalar::from_uniform_bytes(challenge) -- wide/uniform reduction of the 64-byte digest,
	// the same primitive GenerateRistrettoKeypair uses to turn 64 random bytes into a scalar.
	e, err := ristretto255.NewScalar().SetUniformBytes(challenge[:])
	if err != nil {
		return nil, fmt.Errorf("p2p: deriving identity signature challenge scalar: %w", err)
	}

	// s = e*secretKey + secretNonce (sign_raw_uniform).
	s := ristretto255.NewScalar().Multiply(e, secretKey)
	s.Add(s, secretNonce)

	return &identitypb.IdentitySignature{
		Version:     uint32(identitySignatureVersion),
		Signature:   s.Bytes(),
		PublicNonce: nonceKeypair.Public,
		UpdatedAt:   updatedAt,
	}, nil
}
