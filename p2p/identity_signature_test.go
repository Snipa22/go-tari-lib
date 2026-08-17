package p2p

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/gtank/ristretto255"
)

// TestBuildOurIdentitySignatureIsCryptographicallyValid independently recomputes the Schnorr
// verification equation (`s*G == R + e*P`, the standard Ristretto255 Schnorr verify -- see
// tari-crypto/src/signatures/schnorr.rs, `verify_raw_uniform`) for a signature produced by
// buildOurIdentitySignature, using the exact same challenge construction
// (newCommsCorePeerManagerHasher512(identitySignatureLabel).Chain(...)...) a real Tari peer would
// use to validate it (tari/comms/core/src/peer_manager/identity_signature.rs,
// `IdentitySignature::verify`/`construct_challenge`). This is a Go-only self-consistency check
// (no independent Rust-computed fixture -- see p2p/VERIFICATION.md's Part D addendum), but it
// does prove the signing math itself is internally correct, which the wire-shape-only assertions
// in p2p_test.go do not.
func TestBuildOurIdentitySignatureIsCryptographicallyValid(t *testing.T) {
	staticKeypair, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating static keypair: %v", err)
	}

	sig, err := buildOurIdentitySignature(staticKeypair)
	if err != nil {
		t.Fatalf("buildOurIdentitySignature: %v", err)
	}

	if sig.GetVersion() != identitySignatureVersion {
		t.Fatalf("signature version = %d, want %d", sig.GetVersion(), identitySignatureVersion)
	}
	if len(sig.GetSignature()) != 32 {
		t.Fatalf("signature.Signature = %d bytes, want 32", len(sig.GetSignature()))
	}
	if len(sig.GetPublicNonce()) != 32 {
		t.Fatalf("signature.PublicNonce = %d bytes, want 32", len(sig.GetPublicNonce()))
	}

	// Recompute the challenge exactly as construct_challenge/a real verifying peer would.
	var updatedAtBuf [8]byte
	binary.LittleEndian.PutUint64(updatedAtBuf[:], uint64(sig.GetUpdatedAt()))
	var featuresBuf [4]byte
	binary.LittleEndian.PutUint32(featuresBuf[:], 0)

	challenge := newCommsCorePeerManagerHasher512(identitySignatureLabel).
		Chain(staticKeypair.Public).
		Chain(sig.GetPublicNonce()).
		Chain([]byte{byte(sig.GetVersion())}).
		Chain(updatedAtBuf[:]).
		Chain(featuresBuf[:]).
		Finalize()

	e, err := ristretto255.NewScalar().SetUniformBytes(challenge[:])
	if err != nil {
		t.Fatalf("deriving challenge scalar: %v", err)
	}

	s, err := ristretto255.NewScalar().SetCanonicalBytes(sig.GetSignature())
	if err != nil {
		t.Fatalf("decoding signature scalar: %v", err)
	}
	rPoint, err := ristretto255.NewIdentityElement().SetCanonicalBytes(sig.GetPublicNonce())
	if err != nil {
		t.Fatalf("decoding public nonce point: %v", err)
	}
	pPoint, err := ristretto255.NewIdentityElement().SetCanonicalBytes(staticKeypair.Public)
	if err != nil {
		t.Fatalf("decoding static public key point: %v", err)
	}

	// lhs = s*G
	lhs := ristretto255.NewIdentityElement().ScalarBaseMult(s)

	// rhs = R + e*P
	ePoint := ristretto255.NewIdentityElement().ScalarMult(e, pPoint)
	rhs := ristretto255.NewIdentityElement().Add(rPoint, ePoint)

	if !bytes.Equal(lhs.Bytes(), rhs.Bytes()) {
		t.Fatalf("Schnorr verification failed: s*G (%x) != R + e*P (%x)", lhs.Bytes(), rhs.Bytes())
	}
}

// TestBuildOurIdentitySignatureIsNondeterministic checks that two signatures produced for the
// same static keypair differ (since each uses a fresh random nonce) -- a basic sanity check that
// buildOurIdentitySignature isn't accidentally reusing a fixed nonce, which would leak the
// private key under standard Schnorr nonce-reuse attacks.
func TestBuildOurIdentitySignatureIsNondeterministic(t *testing.T) {
	staticKeypair, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating static keypair: %v", err)
	}

	sig1, err := buildOurIdentitySignature(staticKeypair)
	if err != nil {
		t.Fatalf("buildOurIdentitySignature (1): %v", err)
	}
	sig2, err := buildOurIdentitySignature(staticKeypair)
	if err != nil {
		t.Fatalf("buildOurIdentitySignature (2): %v", err)
	}

	if bytes.Equal(sig1.GetPublicNonce(), sig2.GetPublicNonce()) {
		t.Fatalf("two signatures for the same key reused the same public nonce")
	}
	if bytes.Equal(sig1.GetSignature(), sig2.GetSignature()) {
		t.Fatalf("two signatures for the same key produced the same signature scalar")
	}
}
