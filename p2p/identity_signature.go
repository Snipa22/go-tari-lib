package p2p

import (
	"bytes"
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

// constructIdentitySignatureChallenge reproduces `IdentitySignature::construct_challenge`
// byte-for-byte (source: tari/comms/core/src/peer_manager/identity_signature.rs):
//
//	let challenge = comms_core_peer_manager_domain::<Blake2b<U64>>(IDENTITY_SIGNATURE)
//	    .chain(public_key.as_bytes())
//	    .chain(public_nonce.as_bytes())
//	    .chain(version.to_le_bytes())
//	    .chain(u64::try_from(updated_at.timestamp()).unwrap().to_le_bytes())
//	    .chain(features.bits().to_le_bytes());
//	addresses.into_iter().fold(challenge, |challenge, addr| challenge.chain(addr))
//
// The crucial, previously-buggy detail (see BRIEF2.md) is the final fold over `addresses`: each
// claimed address is chained in, IN ORDER, as its own length-prefixed chunk (`.chain` on a
// DomainSeparatedHasher always length-prefixes -- see hashing.go's Chain doc comment) -- not
// omitted, and not concatenated without framing.
//
// `addr: &Multiaddr` there, and `.chain` takes `impl AsRef<[u8]>` -- `Multiaddr`'s `AsRef<[u8]>`
// impl (rust-multiaddr src/lib.rs) returns its raw BINARY wire encoding, the exact same bytes
// `PeerIdentityMsg.addresses` carries on the wire (see multiaddr.go's doc comment for the full
// chain of evidence). So `addresses` here must already be that same raw binary encoding -- the
// caller is responsible for that (identity.go's ourPeerIdentityMsgBytes/IdentityOptions.Addresses,
// ultimately EncodeMultiaddrString in multiaddr.go), this function does no further encoding of
// its own, exactly mirroring the Rust side doing none either.
func constructIdentitySignatureChallenge(staticPublicKey, publicNonce []byte, version byte, updatedAt int64, features uint32, addresses [][]byte) [64]byte {
	var updatedAtBuf [8]byte
	binary.LittleEndian.PutUint64(updatedAtBuf[:], uint64(updatedAt))

	var featuresBuf [4]byte
	binary.LittleEndian.PutUint32(featuresBuf[:], features)

	hasher := newCommsCorePeerManagerHasher512(identitySignatureLabel).
		Chain(staticPublicKey).
		Chain(publicNonce).
		Chain([]byte{version}).
		Chain(updatedAtBuf[:]).
		Chain(featuresBuf[:])
	for _, addr := range addresses {
		hasher = hasher.Chain(addr)
	}
	return hasher.Finalize()
}

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
// features and addresses MUST be the exact same values the caller is about to put in the
// outgoing PeerIdentityMsg (ourPeerIdentityMsgBytes, identity.go) -- a real Tari peer recomputes
// this challenge from whatever PeerIdentityMsg.features/.addresses it actually received and
// rejects the connection if the signature doesn't match (BRIEF2.md's "THE BUG"). addresses must
// already be each address's raw binary multiaddr encoding (see multiaddr.go), not a UTF-8
// string.
func buildOurIdentitySignature(staticKeypair noise.DHKey, features uint32, addresses [][]byte) (*identitypb.IdentitySignature, error) {
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

	// e = H(P||R||version||updated_at||features||addresses...) -- see
	// constructIdentitySignatureChallenge above.
	challenge := constructIdentitySignatureChallenge(staticKeypair.Public, nonceKeypair.Public, identitySignatureVersion, updatedAt, features, addresses)

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

// VerifyIdentitySignature independently checks whether sig is a cryptographically valid
// IdentitySignature over the claimed (features, addresses), for the peer whose long-term
// identity is staticPublicKey -- reproducing `IdentitySignature::is_valid` (source:
// tari/comms/core/src/peer_manager/identity_signature.rs) and tari-crypto's Schnorr verify
// equation `s*G == R + e*P` (tari-crypto/src/signatures/schnorr.rs, `verify_raw_uniform`; P =
// staticPublicKey, R = sig.PublicNonce, s = sig.Signature, e = the recomputed challenge scalar).
//
// This does NOT replicate `is_valid`'s updated_at freshness checks (negative timestamp / more
// than 1 day in the future) -- those are staleness/liveness policy, not part of the
// cryptographic signature check itself, and irrelevant to this package's synchronous tests. It
// returns (false, nil) for a well-formed but cryptographically invalid signature, and a non-nil
// error only for malformed input (wrong-length keys/points/scalars).
func VerifyIdentitySignature(staticPublicKey []byte, features uint32, addresses [][]byte, sig *IdentitySignature) (bool, error) {
	if sig == nil {
		return false, fmt.Errorf("p2p: VerifyIdentitySignature: nil signature")
	}

	challenge := constructIdentitySignatureChallenge(staticPublicKey, sig.PublicNonce, byte(sig.Version), sig.UpdatedAt, features, addresses)

	e, err := ristretto255.NewScalar().SetUniformBytes(challenge[:])
	if err != nil {
		return false, fmt.Errorf("p2p: VerifyIdentitySignature: deriving challenge scalar: %w", err)
	}
	s, err := ristretto255.NewScalar().SetCanonicalBytes(sig.Signature)
	if err != nil {
		return false, fmt.Errorf("p2p: VerifyIdentitySignature: decoding signature scalar: %w", err)
	}
	rPoint, err := ristretto255.NewIdentityElement().SetCanonicalBytes(sig.PublicNonce)
	if err != nil {
		return false, fmt.Errorf("p2p: VerifyIdentitySignature: decoding public nonce point: %w", err)
	}
	pPoint, err := ristretto255.NewIdentityElement().SetCanonicalBytes(staticPublicKey)
	if err != nil {
		return false, fmt.Errorf("p2p: VerifyIdentitySignature: decoding static public key point: %w", err)
	}

	// lhs = s*G
	lhs := ristretto255.NewIdentityElement().ScalarBaseMult(s)

	// rhs = R + e*P
	ePoint := ristretto255.NewIdentityElement().ScalarMult(e, pPoint)
	rhs := ristretto255.NewIdentityElement().Add(rPoint, ePoint)

	return bytes.Equal(lhs.Bytes(), rhs.Bytes()), nil
}
