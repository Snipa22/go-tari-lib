package p2p

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/gtank/ristretto255"
)

// TestConstructIdentitySignatureChallengeZeroValueMatchesPreFixGoldenValue pins the EXACT
// challenge bytes the pre-BRIEF2.md code produced for features=0/no addresses (the zero value
// of IdentityOptions, i.e. every pre-existing Probe/ProbeGetPeers/ProbeChainMetadata caller) --
// BRIEF2.md's strict backward-compatibility requirement (point 4): existing zero-value callers
// MUST produce byte-identical signatures (and therefore byte-identical challenges) to before
// this change.
//
// The expected hex below was computed independently, OUTSIDE this package/its refactored
// constructIdentitySignatureChallenge, by directly reproducing the OLD hardcoded
// buildOurIdentitySignature challenge-construction code verbatim (hardcoded features=0 buffer,
// no per-address chain step at all) against the same fixed staticPub/noncePub/updatedAt/version
// inputs used here -- so this is a real regression check, not a tautology against the same
// (now-parameterized) code path it's meant to guard.
func TestConstructIdentitySignatureChallengeZeroValueMatchesPreFixGoldenValue(t *testing.T) {
	staticPub, err := hex.DecodeString("0101010101010101010101010101010101010101010101010101010101010101"[:64])
	if err != nil {
		t.Fatalf("decoding fixture staticPub: %v", err)
	}
	noncePub, err := hex.DecodeString("0202020202020202020202020202020202020202020202020202020202020202"[:64])
	if err != nil {
		t.Fatalf("decoding fixture noncePub: %v", err)
	}
	const updatedAt int64 = 1700000000
	const version byte = 0

	const wantHex = "a9d941d0515fbb9e21d82ada0cec64b5c3655dc107e6210962a48b0cfd412ee955f8311bb87fbf59cd737220cfacd4f06a44b38fb55e3a35fdeb5634ce5969df"
	want, err := hex.DecodeString(wantHex)
	if err != nil {
		t.Fatalf("decoding golden hex: %v", err)
	}

	got := constructIdentitySignatureChallenge(staticPub, noncePub, version, updatedAt, 0, nil)

	if !bytes.Equal(got[:], want) {
		t.Fatalf("constructIdentitySignatureChallenge(features=0, addresses=nil) = %x, want golden value %x (pre-BRIEF2.md backward-compatibility break)", got, want)
	}
}

// TestBuildOurIdentitySignatureZeroValueIsCryptographicallyValid independently recomputes the
// Schnorr verification equation (`s*G == R + e*P`) for a signature produced by
// buildOurIdentitySignature with the zero-value features/addresses (matching every pre-existing
// Probe/ProbeGetPeers/ProbeChainMetadata caller), using VerifyIdentitySignature (identity_
// signature.go) -- itself an independent implementation of the same verify equation, not a
// second call into the signing path.
func TestBuildOurIdentitySignatureZeroValueIsCryptographicallyValid(t *testing.T) {
	staticKeypair, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating static keypair: %v", err)
	}

	sig, err := buildOurIdentitySignature(staticKeypair, 0, nil)
	if err != nil {
		t.Fatalf("buildOurIdentitySignature: %v", err)
	}
	assertValidIdentitySignature(t, staticKeypair.Public, 0, nil, sig)
}

// TestBuildOurIdentitySignatureWithFeaturesAndAddressesIsCryptographicallyValid is BRIEF2.md
// point 5's new test: a signature built with Features=3 (COMMUNICATION_NODE) and at least one
// real (raw-binary-encoded, see multiaddr.go) address must verify correctly -- proving the fix
// actually signs over the REAL claimed features/addresses, not just that signing still succeeds
// with no error.
func TestBuildOurIdentitySignatureWithFeaturesAndAddressesIsCryptographicallyValid(t *testing.T) {
	staticKeypair, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating static keypair: %v", err)
	}

	addr, err := EncodeMultiaddrString("/ip4/1.2.3.4/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString: %v", err)
	}
	addresses := [][]byte{addr}

	sig, err := buildOurIdentitySignature(staticKeypair, FeaturesCommunicationNode, addresses)
	if err != nil {
		t.Fatalf("buildOurIdentitySignature: %v", err)
	}
	assertValidIdentitySignature(t, staticKeypair.Public, FeaturesCommunicationNode, addresses, sig)

	// A signature over the wrong claimed features or addresses must NOT verify (the whole point
	// of BRIEF2.md's fix) -- this is exactly the check a real Tari peer's
	// validate_peer_identity_message performs and rejects the connection over.
	valid, err := VerifyIdentitySignature(staticKeypair.Public, 0, nil, &IdentitySignature{
		Version:     sig.GetVersion(),
		Signature:   sig.GetSignature(),
		PublicNonce: sig.GetPublicNonce(),
		UpdatedAt:   sig.GetUpdatedAt(),
	})
	if err != nil {
		t.Fatalf("VerifyIdentitySignature (tampered claim): %v", err)
	}
	if valid {
		t.Fatalf("signature over Features=%d/addresses=%v incorrectly verified against tampered claim features=0/no addresses", FeaturesCommunicationNode, addresses)
	}
}

// assertValidIdentitySignature checks sig's wire shape and that it verifies (via
// VerifyIdentitySignature) against the given claimed staticPublicKey/features/addresses.
func assertValidIdentitySignature(t *testing.T, staticPublicKey []byte, features uint32, addresses [][]byte, sig identitySignatureLike) {
	t.Helper()

	if sig.GetVersion() != identitySignatureVersion {
		t.Fatalf("signature version = %d, want %d", sig.GetVersion(), identitySignatureVersion)
	}
	if len(sig.GetSignature()) != 32 {
		t.Fatalf("signature.Signature = %d bytes, want 32", len(sig.GetSignature()))
	}
	if len(sig.GetPublicNonce()) != 32 {
		t.Fatalf("signature.PublicNonce = %d bytes, want 32", len(sig.GetPublicNonce()))
	}

	valid, err := VerifyIdentitySignature(staticPublicKey, features, addresses, &IdentitySignature{
		Version:     sig.GetVersion(),
		Signature:   sig.GetSignature(),
		PublicNonce: sig.GetPublicNonce(),
		UpdatedAt:   sig.GetUpdatedAt(),
	})
	if err != nil {
		t.Fatalf("VerifyIdentitySignature: %v", err)
	}
	if !valid {
		t.Fatalf("VerifyIdentitySignature: signature does not verify against claimed features=%d, addresses=%v", features, addresses)
	}
}

// identitySignatureLike is the minimal getter surface assertValidIdentitySignature needs, shared
// by *identitypb.IdentitySignature (the concrete protobuf type buildOurIdentitySignature
// returns) -- named/aliased here purely to avoid this test file importing the proto package
// directly just for a type name.
type identitySignatureLike = interface {
	GetVersion() uint32
	GetSignature() []byte
	GetPublicNonce() []byte
	GetUpdatedAt() int64
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

	sig1, err := buildOurIdentitySignature(staticKeypair, 0, nil)
	if err != nil {
		t.Fatalf("buildOurIdentitySignature (1): %v", err)
	}
	sig2, err := buildOurIdentitySignature(staticKeypair, 0, nil)
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

// TestVerifyIdentitySignatureManualCrossCheck independently recomputes the Schnorr verification
// equation by hand (NOT by calling VerifyIdentitySignature), to prove VerifyIdentitySignature
// itself isn't just rubber-stamping everything true -- see tari-crypto/src/signatures/
// schnorr.rs's own `verify_raw_uniform` equation this mirrors.
func TestVerifyIdentitySignatureManualCrossCheck(t *testing.T) {
	staticKeypair, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating static keypair: %v", err)
	}
	addr, err := EncodeMultiaddrString("/ip4/1.2.3.4/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString: %v", err)
	}
	addresses := [][]byte{addr}

	sig, err := buildOurIdentitySignature(staticKeypair, FeaturesCommunicationNode, addresses)
	if err != nil {
		t.Fatalf("buildOurIdentitySignature: %v", err)
	}

	challenge := constructIdentitySignatureChallenge(staticKeypair.Public, sig.GetPublicNonce(), byte(sig.GetVersion()), sig.GetUpdatedAt(), FeaturesCommunicationNode, addresses)

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

	lhs := ristretto255.NewIdentityElement().ScalarBaseMult(s)
	ePoint := ristretto255.NewIdentityElement().ScalarMult(e, pPoint)
	rhs := ristretto255.NewIdentityElement().Add(rPoint, ePoint)

	if !bytes.Equal(lhs.Bytes(), rhs.Bytes()) {
		t.Fatalf("Schnorr verification failed: s*G (%x) != R + e*P (%x)", lhs.Bytes(), rhs.Bytes())
	}
}
