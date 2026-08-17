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
	writeLengthPrefixedTo(h.digest, []byte(domainSeparationTag(domain, version, label)))
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
	writeLengthPrefixedTo(h.digest, data)
	return h
}

// Finalize returns the 32-byte Blake2b-256 digest. It does not add any further framing, matching
// Rust's plain `.finalize()`/`.finalize_into(...)`.
func (h *DomainSeparatedHasher) Finalize() [32]byte {
	var out [32]byte
	h.digest.Sum(out[:0])
	return out
}

// writeLengthPrefixedTo writes `u64_LE(len(data))` followed by `data` into digest. hash.Hash.
// Write never returns an error (per the stdlib hash.Hash contract), so errors are deliberately
// not propagated here. Factored out of DomainSeparatedHasher so DomainSeparatedHasher512 (below)
// can share the exact same tag-building/length-prefix-framing logic instead of duplicating it
// and risking the two variants drifting apart.
func writeLengthPrefixedTo(digest hash.Hash, data []byte) {
	var lenBuf [8]byte
	binary.LittleEndian.PutUint64(lenBuf[:], uint64(len(data)))
	_, _ = digest.Write(lenBuf[:])
	_, _ = digest.Write(data)
}

// DomainSeparatedHasher512 is the `Blake2b<U64>` (Blake2b-512, 64-byte digest) counterpart to
// DomainSeparatedHasher (`Blake2b<U32>`, 32-byte digest). Tari's `IdentitySignature::
// construct_challenge` (source: tari/comms/core/src/peer_manager/identity_signature.rs) is the
// only user of this variant in this package: it needs a 64-byte "uniform bytes" digest to feed
// into Ristretto255 scalar wide/uniform reduction (`Scalar::from_uniform_bytes`/this repo's
// `ristretto255.Scalar.SetUniformBytes`, which requires exactly 64 bytes of input), not the
// 32-byte digest the Noise DH KDF uses. Shares the exact same tag-building
// (domainSeparationTag) and length-prefix-chaining (writeLengthPrefixedTo) logic as
// DomainSeparatedHasher above -- only the underlying digest algorithm/output size differs.
type DomainSeparatedHasher512 struct {
	digest hash.Hash
}

// NewDomainSeparatedHasher512 starts a new domain-separated Blake2b-512 hash construction,
// equivalent to `DomainSeparatedHasher::<Blake2b<U64>, M>::new_with_label(label)`.
func NewDomainSeparatedHasher512(domain string, version uint64, label string) *DomainSeparatedHasher512 {
	// blake2b.New512(nil) only ever errors if given a key/config longer than the digest allows;
	// with a nil key that can never happen, so the error is deliberately not surfaced here,
	// mirroring NewDomainSeparatedHasher above.
	digest, err := blake2b.New512(nil)
	if err != nil {
		panic(fmt.Sprintf("p2p: blake2b.New512(nil) unexpectedly failed: %v", err))
	}
	h := &DomainSeparatedHasher512{digest: digest}
	writeLengthPrefixedTo(h.digest, []byte(domainSeparationTag(domain, version, label)))
	return h
}

// Chain feeds a length-prefixed chunk of data into the hasher and returns the hasher for
// chaining, matching DomainSeparatedHasher.Chain.
func (h *DomainSeparatedHasher512) Chain(data []byte) *DomainSeparatedHasher512 {
	writeLengthPrefixedTo(h.digest, data)
	return h
}

// Finalize returns the 64-byte Blake2b-512 digest, with no further framing.
func (h *DomainSeparatedHasher512) Finalize() [64]byte {
	var out [64]byte
	h.digest.Sum(out[:0])
	return out
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

// CommsCorePeerManagerDomain is the domain separation tag used by Tari's comms/core crate for
// peer-manager-related signing, currently just the identity signature challenge (source:
// `tari/comms/core/src/peer_manager/hashing.rs`):
//
//	hash_domain!(CommsCorePeerManagerDomain, "com.tari.comms.core.peer_manager", 1);
//
// Note this is version 1 (explicit 3-arg macro form), NOT version 0 like CommsCoreHashDomain
// above -- a different hash_domain! invocation in a different Rust source file, with its own
// independently-chosen version number; don't assume the two domains share a version just because
// they share a "com.tari.comms.core" prefix.
const (
	CommsCorePeerManagerDomainName    = "com.tari.comms.core.peer_manager"
	CommsCorePeerManagerDomainVersion = 1
)

// identitySignatureLabel is `IDENTITY_SIGNATURE` (source:
// `tari/comms/core/src/peer_manager/hashing.rs`), the label used when hashing an identity
// signature's challenge.
const identitySignatureLabel = "identity_signature"

// newCommsCorePeerManagerHasher512 starts a DomainSeparatedHasher512 scoped to
// CommsCorePeerManagerDomain with the given label, i.e.
// `DomainSeparatedHasher::<Blake2b<U64>, CommsCorePeerManagerDomain>::new_with_label(label)`.
func newCommsCorePeerManagerHasher512(label string) *DomainSeparatedHasher512 {
	return NewDomainSeparatedHasher512(CommsCorePeerManagerDomainName, CommsCorePeerManagerDomainVersion, label)
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
