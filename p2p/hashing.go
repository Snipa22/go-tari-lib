package p2p

import (
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/blake2b"
)

// DomainSeparatedHasher reproduces the construction of
// `tari_crypto::hashing::DomainSeparatedHasher<D, M>` (source: tari-crypto/src/hashing.rs,
// `main` branch, github.com/tari-project/tari-crypto).
//
// Construction (see `new_with_label`, `chain`/`update`, `finalize` in the Rust source, and the
// `deconstruction`/`domain_separation_tag_hashing` unit tests transcribed below):
//
//  1. Build the domain separation tag: `tag = "{domain}.v{version}.{label}"` if label is
//     non-empty, else `tag = "{domain}.v{version}"`.
//  2. Initialize a fresh digest.
//  3. Feed the tag into the digest as a length-prefixed chunk:
//     `digest.update(u64_LE(len(tag)))` then `digest.update(tag_bytes)`.
//  4. For every subsequent `.chain(data)` call: feed `u64_LE(len(data))` then `data` into the
//     digest (length-prefixed framing again, NOT raw concatenation).
//  5. `.Finalize()` is a plain digest finalize; no extra framing at the end.
//
// This repo only ever needs `Blake2b<U32>` (32-byte/256-bit Blake2b output) as the underlying
// digest `D`, so this type is hardcoded to that rather than being generic over the digest
// algorithm the way the Rust type is generic over `D`.
type DomainSeparatedHasher struct {
	digest hash.Hash
}

// NewDomainSeparatedHasher starts a new domain-separated Blake2b-256 hash construction for the
// given domain, version and label, equivalent to
// `DomainSeparatedHasher::<Blake2b<U32>, M>::new_with_label(label)` where `M::domain() ==
// domain` and `M::version() == version`.
func NewDomainSeparatedHasher(domain string, version uint64, label string) *DomainSeparatedHasher {
	// blake2b.New256(nil) only ever errors if given a key/config longer than the digest allows;
	// with a nil key that can never happen, so the error is deliberately not surfaced in this
	// constructor's signature (mirrors the Rust side, where `Blake2b::<U32>::new()` cannot fail
	// either).
	digest, err := blake2b.New256(nil)
	if err != nil {
		panic(fmt.Sprintf("p2p: blake2b.New256(nil) unexpectedly failed: %v", err))
	}
	h := &DomainSeparatedHasher{digest: digest}
	h.writeLengthPrefixed([]byte(domainSeparationTag(domain, version, label)))
	return h
}

// domainSeparationTag builds "{domain}.v{version}.{label}", or "{domain}.v{version}" if label
// is empty, matching `DomainSeparation::domain_separation_tag` in the Rust source.
func domainSeparationTag(domain string, version uint64, label string) string {
	if label == "" {
		return fmt.Sprintf("%s.v%d", domain, version)
	}
	return fmt.Sprintf("%s.v%d.%s", domain, version, label)
}

// Chain feeds a length-prefixed chunk of data into the hasher and returns the hasher for
// chaining, equivalent to Rust's `DomainSeparatedHasher::chain`/`digest::Update::chain`.
func (h *DomainSeparatedHasher) Chain(data []byte) *DomainSeparatedHasher {
	h.writeLengthPrefixed(data)
	return h
}

// Finalize returns the 32-byte Blake2b-256 digest. It does not add any further framing, matching
// Rust's plain `.finalize()`/`.finalize_into(...)`.
func (h *DomainSeparatedHasher) Finalize() [32]byte {
	var out [32]byte
	h.digest.Sum(out[:0])
	return out
}

// writeLengthPrefixed writes `u64_LE(len(data))` followed by `data` into the underlying digest.
// hash.Hash.Write never returns an error (per the stdlib hash.Hash contract), so errors are
// deliberately not propagated here.
func (h *DomainSeparatedHasher) writeLengthPrefixed(data []byte) {
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(data)))
	_, _ = h.digest.Write(lenBuf[:])
	_, _ = h.digest.Write(data)
}

// CommsCoreHashDomain is the domain separation tag used by Tari's comms/core crate for all
// Noise-related key derivation (source: `tari/comms/core/src/types.rs`):
//
//	hash_domain!(CommsCoreHashDomain, "com.tari.comms.core", 0);
//
// Note this explicitly passes version 0, NOT the `hash_domain!` 2-arg macro form's implicit
// default of version 1 (compare with the `TestDomain` fixture in hashing_test.go, which does use
// the 2-arg/version-1 default). Getting this version number wrong would silently produce a
// completely different (and wrong) KDF output that would only fail once tested against a real
// peer, so it is called out explicitly here.
const (
	CommsCoreHashDomainName    = "com.tari.comms.core"
	CommsCoreHashDomainVersion = 0
)

// noiseDHKDFLabel is the label Tari uses when deriving the Noise DH KDF key (source:
// `tari/comms/core/src/noise/crypto_resolver.rs`, `noise_kdf`).
const noiseDHKDFLabel = "noise.dh"

// newCommsCoreHasher starts a DomainSeparatedHasher scoped to CommsCoreHashDomain with the given
// label, i.e. `DomainSeparatedHasher::<Blake2b<U32>, CommsCoreHashDomain>::new_with_label(label)`.
func newCommsCoreHasher(label string) *DomainSeparatedHasher {
	return NewDomainSeparatedHasher(CommsCoreHashDomainName, CommsCoreHashDomainVersion, label)
}

// noiseDHKDF is the domain-separated Blake2b-256 KDF Tari applies to a raw Ristretto255
// Diffie-Hellman shared-secret point encoding before handing the result to snow/flynn-noise as
// the "DH output" (source: `tari/comms/core/src/noise/crypto_resolver.rs`, `noise_kdf`):
//
//	fn noise_kdf(shared_key: &CommsDHKE) -> CommsNoiseKey {
//	    TariCommsNoiseHasher::new_with_label("noise.dh")
//	        .chain(shared_key.as_bytes())
//	        .finalize_into(...) // 32 bytes output
//	}
//
// The tag construction (`"com.tari.comms.core.v0.noise.dh"`) reuses the byte-exact-verified
// generic hasher above; the raw Ristretto255 DH math fed into it is NOT independently
// cross-verified against a real Rust `tari_crypto` run in this environment -- see
// p2p/VERIFICATION.md.
func noiseDHKDF(sharedSecret []byte) []byte {
	sum := newCommsCoreHasher(noiseDHKDFLabel).Chain(sharedSecret).Finalize()
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}
