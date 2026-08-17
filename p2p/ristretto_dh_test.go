package p2p

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/gtank/ristretto255"
)

// TestRistrettoKeypairRoundTrip is a Go-only sanity check (not cross-verified against Rust, see
// p2p/VERIFICATION.md): keypair generation produces a 32-byte private scalar and 32-byte public
// point whose encodings round-trip through canonical decode without error.
func TestRistrettoKeypairRoundTrip(t *testing.T) {
	kp, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("GenerateRistrettoKeypair: %v", err)
	}
	if len(kp.Private) != 32 {
		t.Fatalf("expected 32-byte private key, got %d bytes", len(kp.Private))
	}
	if len(kp.Public) != 32 {
		t.Fatalf("expected 32-byte public key, got %d bytes", len(kp.Public))
	}

	if _, err := ristretto255.NewScalar().SetCanonicalBytes(kp.Private); err != nil {
		t.Fatalf("private key is not a canonical ristretto255 scalar encoding: %v", err)
	}
	if _, err := ristretto255.NewIdentityElement().SetCanonicalBytes(kp.Public); err != nil {
		t.Fatalf("public key is not a canonical ristretto255 point encoding: %v", err)
	}

	// The public key must actually be privateScalar * basepoint.
	scalar, err := ristretto255.NewScalar().SetCanonicalBytes(kp.Private)
	if err != nil {
		t.Fatalf("re-decoding private scalar: %v", err)
	}
	wantPublic := ristretto255.NewIdentityElement().ScalarBaseMult(scalar)
	if !bytes.Equal(wantPublic.Bytes(), kp.Public) {
		t.Fatalf("public key does not equal private*basepoint:\n got  %x\n want %x", kp.Public, wantPublic.Bytes())
	}
}

// TestRistrettoDHAgreement is a Go-only sanity check (not cross-verified against Rust): two
// independently generated keypairs must agree on the raw DH shared point BEFORE the KDF is
// applied (A_priv * B_pub == B_priv * A_pub, standard DH symmetry), tested as a distinct
// assertion from the post-KDF agreement below, per P2P_SPEC.md section 8 point 2.
func TestRistrettoDHAgreement(t *testing.T) {
	aScalar, err := ristretto255.NewScalar().SetUniformBytes(random64(t))
	if err != nil {
		t.Fatalf("generating scalar A: %v", err)
	}
	bScalar, err := ristretto255.NewScalar().SetUniformBytes(random64(t))
	if err != nil {
		t.Fatalf("generating scalar B: %v", err)
	}

	aPublic := ristretto255.NewIdentityElement().ScalarBaseMult(aScalar)
	bPublic := ristretto255.NewIdentityElement().ScalarBaseMult(bScalar)

	// Raw DH agreement, before the KDF: A_priv * B_pub == B_priv * A_pub.
	sharedFromA := ristretto255.NewIdentityElement().ScalarMult(aScalar, bPublic)
	sharedFromB := ristretto255.NewIdentityElement().ScalarMult(bScalar, aPublic)
	if !bytes.Equal(sharedFromA.Bytes(), sharedFromB.Bytes()) {
		t.Fatalf("raw ristretto255 DH shared points disagree:\n fromA %x\n fromB %x", sharedFromA.Bytes(), sharedFromB.Bytes())
	}

	// Post-KDF agreement: RistrettoDH.DH must produce the same output on both sides, since it's
	// a pure function of the (identical) raw shared point.
	dh := RistrettoDH{}
	outFromA, err := dh.DH(aScalar.Bytes(), bPublic.Bytes())
	if err != nil {
		t.Fatalf("dh.DH from A's perspective: %v", err)
	}
	outFromB, err := dh.DH(bScalar.Bytes(), aPublic.Bytes())
	if err != nil {
		t.Fatalf("dh.DH from B's perspective: %v", err)
	}
	if !bytes.Equal(outFromA, outFromB) {
		t.Fatalf("post-KDF DH outputs disagree:\n fromA %x\n fromB %x", outFromA, outFromB)
	}
	if len(outFromA) != 32 {
		t.Fatalf("expected 32-byte DH output, got %d bytes", len(outFromA))
	}

	// The post-KDF output must differ from the raw shared point (i.e. the KDF actually ran).
	if bytes.Equal(outFromA, sharedFromA.Bytes()) {
		t.Fatalf("post-KDF DH output equals the raw shared point; KDF was not applied")
	}
}

// TestRistrettoDHRejectsNonCanonicalPublicKey checks that DH() rejects a public key encoding
// that is not a valid canonical Ristretto255 point (all-0xFF bytes, out of range for the field).
func TestRistrettoDHRejectsNonCanonicalPublicKey(t *testing.T) {
	dh := RistrettoDH{}
	kp, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("GenerateRistrettoKeypair: %v", err)
	}

	badPub := bytes.Repeat([]byte{0xFF}, 32)
	if _, err := dh.DH(kp.Private, badPub); err == nil {
		t.Fatalf("expected DH to reject a non-canonical public key encoding, got nil error")
	}
}

// TestRistrettoDHLenAndName checks the fixed metadata methods.
func TestRistrettoDHLenAndName(t *testing.T) {
	dh := RistrettoDH{}
	if dh.DHLen() != 32 {
		t.Fatalf("DHLen() = %d, want 32", dh.DHLen())
	}
	if dh.DHName() != "25519" {
		t.Fatalf("DHName() = %q, want %q", dh.DHName(), "25519")
	}
}

func random64(t *testing.T) []byte {
	t.Helper()
	buf := make([]byte, 64)
	if _, err := rand.Read(buf); err != nil {
		t.Fatalf("reading randomness: %v", err)
	}
	return buf
}
