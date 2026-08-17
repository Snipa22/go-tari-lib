package p2p

import (
	"bytes"
	"encoding/binary"
	"testing"

	"golang.org/x/crypto/blake2b"
)

// blake2b256 hashes the given already-fully-framed byte sequence with a plain Blake2b-256,
// matching Rust's `Blake2b::<U32>::new().chain(...).finalize()` used directly (not through
// DomainSeparatedHasher) in tari-crypto's own test fixtures. This lets the tests below build the
// expected digest independently of the DomainSeparatedHasher implementation under test.
func blake2b256(chunks ...[]byte) [32]byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	for _, c := range chunks {
		_, _ = h.Write(c)
	}
	var out [32]byte
	h.Sum(out[:0])
	return out
}

func le64(n uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], n)
	return b[:]
}

// TestDeconstructionVector reproduces tari-crypto's own Rust unit test `deconstruction`
// (tari-crypto/src/hashing.rs, `main` branch), byte-for-byte:
//
//	hash_domain!(TestDomain, "com.tari.generic"); // 2-arg macro form => version defaults to 1
//	let hash = DomainSeparatedHasher::<Blake2b<U32>, TestDomain>::new_with_label("mytest")
//	    .chain("rincewind")
//	    .chain("hex")
//	    .finalize();
//	let expected = Blake2b::<U32>::new()
//	    .chain(26u64.to_le_bytes())                      // len("com.tari.generic.v1.mytest") == 26
//	    .chain("com.tari.generic.v1.mytest".as_bytes())
//	    .chain(9u64.to_le_bytes())
//	    .chain("rincewind".as_bytes())
//	    .chain(3u64.to_le_bytes())
//	    .chain("hex".as_bytes())
//	    .finalize();
//	assert_eq!(hash.as_ref(), expected.as_slice());
//
// This is byte-exact verified against real Tari Rust source: the exact byte sequence being
// hashed is fully pinned down by the Rust test above (domain, version-default-of-1, label and
// chained inputs are all taken verbatim from it), and Blake2b-256 is a standard, deterministic,
// cross-language-identical algorithm (RFC 7693) -- so computing it here in Go over that same
// pinned byte sequence is equivalent to having it computed by the real Rust code.
func TestDeconstructionVector(t *testing.T) {
	const domain = "com.tari.generic"
	const version = 1 // hash_domain!(TestDomain, "com.tari.generic") 2-arg form defaults to v1
	const label = "mytest"

	tag := domainSeparationTag(domain, version, label)
	if tag != "com.tari.generic.v1.mytest" {
		t.Fatalf("unexpected tag: %q", tag)
	}
	if len(tag) != 26 {
		t.Fatalf("expected tag length 26, got %d", len(tag))
	}

	got := NewDomainSeparatedHasher(domain, version, label).
		Chain([]byte("rincewind")).
		Chain([]byte("hex")).
		Finalize()

	want := blake2b256(
		le64(uint64(len(tag))), []byte(tag),
		le64(9), []byte("rincewind"),
		le64(3), []byte("hex"),
	)

	if !bytes.Equal(got[:], want[:]) {
		t.Fatalf("deconstruction vector mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestDomainSeparationTagHashingVector reproduces tari-crypto's Rust unit test
// `domain_separation_tag_hashing` (tari-crypto/src/hashing.rs, `main` branch), byte-for-byte:
//
//	// domain="com.discworld", version=42, label="turtles" -> tag = "com.discworld.v42.turtles" (len 25)
//	let hash = DomainSeparatedHasher::<Blake2b<U32>, MyDemoHasher>::new_with_label("turtles").finalize();
//	let expected = Blake2b::<U32>::default()
//	    .chain((25u64).to_le_bytes())
//	    .chain("com.discworld.v42.turtles".as_bytes())
//	    .finalize();
//	assert_eq!(hash.as_ref(), expected.as_slice());
//
// Byte-exact verified against real Tari Rust source, on the same grounds as
// TestDeconstructionVector above.
func TestDomainSeparationTagHashingVector(t *testing.T) {
	const domain = "com.discworld"
	const version = 42
	const label = "turtles"

	tag := domainSeparationTag(domain, version, label)
	if tag != "com.discworld.v42.turtles" {
		t.Fatalf("unexpected tag: %q", tag)
	}
	if len(tag) != 25 {
		t.Fatalf("expected tag length 25, got %d", len(tag))
	}

	got := NewDomainSeparatedHasher(domain, version, label).Finalize()

	want := blake2b256(le64(uint64(len(tag))), []byte(tag))

	if !bytes.Equal(got[:], want[:]) {
		t.Fatalf("domain_separation_tag_hashing vector mismatch:\n got  %x\n want %x", got, want)
	}
}

// TestCommsCoreHashDomainNoiseDHTag asserts the exact CommsCoreHashDomain/"noise.dh" tag
// construction used by the Noise DH KDF (source: tari/comms/core/src/types.rs +
// tari/comms/core/src/noise/crypto_resolver.rs). This tag construction reuses the
// byte-exact-verified generic hasher exercised above; there is no independent Rust-side DH
// output fixture to compare the *value* of noiseDHKDF's result against in this environment (no
// cargo/rustc available, crates.io unreachable, 2026-08-17) -- see p2p/VERIFICATION.md.
func TestCommsCoreHashDomainNoiseDHTag(t *testing.T) {
	tag := domainSeparationTag(CommsCoreHashDomainName, CommsCoreHashDomainVersion, noiseDHKDFLabel)
	const want = "com.tari.comms.core.v0.noise.dh"
	if tag != want {
		t.Fatalf("unexpected CommsCoreHashDomain noise.dh tag: got %q, want %q", tag, want)
	}
	if len(tag) != 31 {
		t.Fatalf("expected tag length 31, got %d", len(tag))
	}

	got := newCommsCoreHasher(noiseDHKDFLabel).Finalize()
	wantHash := blake2b256(le64(uint64(len(tag))), []byte(tag))
	if !bytes.Equal(got[:], wantHash[:]) {
		t.Fatalf("noise.dh tag hash mismatch:\n got  %x\n want %x", got, wantHash)
	}
}

// TestNoiseDHKDFIsDeterministicAndDomainSeparated is a Go-only sanity check (not cross-verified
// against Rust): the same shared-secret bytes always produce the same KDF output, and different
// labels/shared-secrets produce different output.
func TestNoiseDHKDFIsDeterministicAndDomainSeparated(t *testing.T) {
	secretA := bytes.Repeat([]byte{0x11}, 32)
	secretB := bytes.Repeat([]byte{0x22}, 32)

	a1 := noiseDHKDF(secretA)
	a2 := noiseDHKDF(secretA)
	if !bytes.Equal(a1, a2) {
		t.Fatalf("noiseDHKDF is not deterministic: %x != %x", a1, a2)
	}

	b := noiseDHKDF(secretB)
	if bytes.Equal(a1, b) {
		t.Fatalf("noiseDHKDF produced identical output for different inputs")
	}

	if len(a1) != 32 {
		t.Fatalf("expected 32-byte KDF output, got %d bytes", len(a1))
	}
}
