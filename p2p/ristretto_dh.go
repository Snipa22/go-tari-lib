package p2p

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/flynn/noise"
	"github.com/gtank/ristretto255"
)

// RistrettoDH implements `noise.DHFunc` (github.com/flynn/noise) using Ristretto255
// scalar/point arithmetic, matching Tari's custom snow `CryptoResolver` DH implementation
// (source: tari/comms/core/src/noise/crypto_resolver.rs, `CommsDiffieHellman`/`impl Dh for
// CommsDiffieHellman`):
//
//	impl Dh for CommsDiffieHellman {
//	    fn name(&self) -> &'static str { "Ristretto" }
//	    fn pub_len(&self) -> usize { 32 }
//	    fn priv_len(&self) -> usize { 32 }
//	    fn dh(&self, public_key: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
//	        let pk = UncompressedCommsPublicKey::from_canonical_bytes(&public_key[..32])?;
//	        let shared = CommsDHKE::new(&self.secret_key, &pk); // shared = secret_key * pk
//	        let hash = noise_kdf(&shared);                      // domain-separated Blake2b-256 KDF
//	        out.copy_from_slice(hash.reveal());
//	        Ok(())
//	    }
//	}
//
// `CommsDHKE::new(sk, pk) = sk * pk` is a standard Ristretto255 scalar-point multiplication, no
// cofactor/clamping tricks (source: tari-crypto/src/dhke.rs, `DiffieHellmanSharedSecret::new`).
//
// DHName naming quirk: Tari's Rust-side Dh::name() returns "Ristretto", but the *Noise protocol
// name string* Tari actually parses/advertises is the literal constant
// "Noise_XX_25519_ChaChaPoly_BLAKE2b" (source: tari/comms/core/src/noise/config.rs,
// NOISE_PARAMETERS) -- i.e. Tari deliberately keeps the "25519" slot in the protocol name string
// even though the DH plugged in via its custom CryptoResolver is Ristretto255, not X25519.
// flynn/noise's `NewCipherSuite` builds its own name string as
// `dh.DHName()+"_"+cipher.CipherName()+"_"+hash.HashName()`; DHName() below returns "25519" so
// the resulting suite name string is "25519_ChaChaPoly_BLAKE2b", matching the non-DH-name parts
// of Tari's constant. Noise protocol name strings are NOT transmitted over the wire in the XX
// handshake (only implicit via prologue + matching primitive choices), so this string is not
// load-bearing for interop -- do not "fix" it to say "Ristretto" thinking it matters; what
// actually matters for interop is the prologue, pattern, cipher/hash choice, and (most
// importantly) the DH math itself, all of which match Tari's real behaviour.
type RistrettoDH struct{}

var _ noise.DHFunc = RistrettoDH{}

// GenerateRistrettoKeypair is a convenience wrapper around
// RistrettoDH{}.GenerateKeypair(rand.Reader).
func GenerateRistrettoKeypair() (noise.DHKey, error) {
	return RistrettoDH{}.GenerateKeypair(rand.Reader)
}

// GenerateKeypair samples a uniformly random Ristretto255 scalar as the private key (via 64
// uniformly random bytes reduced mod the group order, per gtank/ristretto255's
// `Scalar.SetUniformBytes` -- the standard way to obtain a uniform scalar from randomness with
// that API, since this ristretto255 package version doesn't expose an `Scalar.Rand` method), and
// derives the public key as `scalar * B` (the canonical Ristretto255 generator/basepoint), both
// canonically encoded to 32 bytes.
func (RistrettoDH) GenerateKeypair(random io.Reader) (noise.DHKey, error) {
	if random == nil {
		random = rand.Reader
	}

	var seed [64]byte
	if _, err := io.ReadFull(random, seed[:]); err != nil {
		return noise.DHKey{}, fmt.Errorf("p2p: reading randomness for ristretto255 keypair: %w", err)
	}

	scalar, err := ristretto255.NewScalar().SetUniformBytes(seed[:])
	if err != nil {
		// SetUniformBytes only fails if given input that isn't exactly 64 bytes; seed is a
		// fixed-size [64]byte array, so this branch should be unreachable.
		return noise.DHKey{}, fmt.Errorf("p2p: deriving ristretto255 scalar from randomness: %w", err)
	}

	public := ristretto255.NewIdentityElement().ScalarBaseMult(scalar)

	return noise.DHKey{
		Private: scalar.Bytes(),
		Public:  public.Bytes(),
	}, nil
}

// DH decodes `privkey` as a Ristretto255 scalar and `pubkey` as a Ristretto255 group element
// (rejecting either if not a canonical encoding, matching Rust's `from_canonical_bytes`, which
// errors on non-canonical input), computes `shared = privkey * pubkey` (scalar-point
// multiplication), canonically encodes the resulting point to 32 bytes, and then runs those 32
// bytes through the domain-separated Blake2b-256 KDF (noiseDHKDF, label "noise.dh", domain
// CommsCoreHashDomain) -- returning the 32-byte KDF output as the "DH output" fed into
// flynn/noise's internal chaining-key mixing, NOT the raw DH point. This exactly mirrors Tari's
// `CommsDiffieHellman::dh` (see type doc comment above).
func (RistrettoDH) DH(privkey, pubkey []byte) ([]byte, error) {
	if len(privkey) != 32 {
		return nil, fmt.Errorf("p2p: ristretto255 private key must be 32 bytes, got %d", len(privkey))
	}
	if len(pubkey) != 32 {
		return nil, fmt.Errorf("p2p: ristretto255 public key must be 32 bytes, got %d", len(pubkey))
	}

	scalar, err := ristretto255.NewScalar().SetCanonicalBytes(privkey)
	if err != nil {
		return nil, fmt.Errorf("p2p: invalid ristretto255 private scalar (non-canonical encoding): %w", err)
	}

	point, err := ristretto255.NewIdentityElement().SetCanonicalBytes(pubkey)
	if err != nil {
		return nil, fmt.Errorf("p2p: invalid ristretto255 public point (non-canonical encoding): %w", err)
	}

	shared := ristretto255.NewIdentityElement().ScalarMult(scalar, point)

	return noiseDHKDF(shared.Bytes()), nil
}

// DHLen returns 32, the size in bytes of both the raw Ristretto255 point encoding and (not
// coincidentally) the Blake2b-256 KDF output that DH() actually returns.
func (RistrettoDH) DHLen() int { return 32 }

// DHName returns "25519" -- see the deliberate naming-quirk explanation in the type doc comment
// above. This is NOT a claim that the DH function is X25519; it is Ristretto255 end to end.
func (RistrettoDH) DHName() string { return "25519" }
