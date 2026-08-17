# Task: implement `p2p` package — Tari P2P (tari_comms) Noise_XX client handshake

Module: `github.com/Snipa22/go-tari-lib`. New package at `p2p/` (importable as
`github.com/Snipa22/go-tari-lib/p2p`). Do NOT touch `nodeGRPC/` or `walletGRPC/`.

All protocol details below were extracted directly from the real Tari Rust source
(github.com/tari-project/tari `development` branch, github.com/tari-project/tari-crypto `main`
branch) on 2026-08-17. Treat every byte-layout detail as load-bearing and exact — this is not
a rough approximation, it's a literal transcription. Cite the source file for each primitive
in a doc comment above its implementation.

NOTE: No Rust toolchain is available in this sandbox (no `cargo`/`rustc`; crates.io API is
blocked with 403 for this network). We could NOT cross-compile a Rust harness to generate
byte-exact test vectors. Compensate with: (a) faithfully transcribing the exact Rust algorithms
below (verified against real source, quoted inline), (b) a hand-computed-by-hand test vector
for the domain-separated hasher construction using the ACTUAL Rust unit test fixture given
below (this one we CAN verify byte-exact, because Tari's own Rust test suite published the
expected hash output for a known input — use it as a real cross-checked fixture), and (c)
thorough Go-only round-trip tests. Explicitly comment in code + final report which pieces are
"byte-exact verified against a real Tari Rust test vector" vs "internally-consistent Go-only,
not independently cross-verified."

## 1. Domain-separated hasher (`tari_crypto::hashing::DomainSeparatedHasher`)

Source: `tari-crypto/src/hashing.rs` (main branch).

Construction for `DomainSeparatedHasher<D, M>::new_with_label(label)`:
1. Build the domain separation tag string: `tag = "{domain}.v{version}.{label}"` if label is
   non-empty, else `tag = "{domain}.v{version}"`. `domain` and `version` come from the
   `DomainSeparation` trait impl (a `hash_domain!(Name, "domain.string", version)` macro
   invocation elsewhere in Tari).
2. Initialize the underlying digest `D` (fresh/empty state).
3. Feed the tag into the digest as a **length-prefixed** chunk: `digest.update(u64_LE(len(tag)))`
   then `digest.update(tag_bytes)`. (This is exactly equivalent to what `add_domain_separation_tag`
   does — it just builds the same bytes without materializing the intermediate string; the net
   effect, confirmed by Tari's own unit test `deconstruction`, is length-prefix-then-tag.)
4. For every subsequent `.chain(data)` / `.update(data)` call: feed `u64_LE(len(data))` then
   `data` into the digest (again, length-prescriptive framing, NOT just raw concatenation).
5. `.finalize()` / `.finalize_into(...)` is a normal digest finalize — no extra framing at the end.

**REAL CROSS-CHECKED TEST VECTOR** (from tari-crypto's own Rust test suite, `hashing.rs`
`#[test] fn deconstruction()` — hard-code this as a Go test fixture, this is byte-exact
Rust-verified ground truth, not something we invented):

```rust
hash_domain!(TestDomain, "com.tari.generic"); // version defaults to 1 (2-arg macro form)
let hash = DomainSeparatedHasher::<Blake2b<U32>, TestDomain>::new_with_label("mytest")
    .chain("rincewind")
    .chain("hex")
    .finalize();
let expected = Blake2b::<U32>::new()
    .chain(26u64.to_le_bytes())                      // len("com.tari.generic.v1.mytest") == 26
    .chain("com.tari.generic.v1.mytest".as_bytes())
    .chain(9u64.to_le_bytes())
    .chain("rincewind".as_bytes())
    .chain(3u64.to_le_bytes())
    .chain("hex".as_bytes())
    .finalize();
assert_eq!(hash.as_ref(), expected.as_slice());
```

There's also this simpler one from the same file (`domain_separation_tag_hashing` test), useful
for a second fixture:
```rust
// domain="com.discworld", version=42, label="turtles" -> tag = "com.discworld.v42.turtles" (len 25)
let hash = DomainSeparatedHasher::<Blake2b<U32>, MyDemoHasher>::new_with_label("turtles").finalize();
let expected = Blake2b::<U32>::default()
    .chain((25u64).to_le_bytes())
    .chain("com.discworld.v42.turtles".as_bytes())
    .finalize();
assert_eq!(hash.as_ref(), expected.as_slice());
```

**Your Go implementation of this generic domain-separated-hasher primitive MUST reproduce both
of the above test vectors exactly** (compute the Blake2b-256 digest yourself in Go using
`golang.org/x/crypto/blake2b` with a 32-byte output size, no key) — write real Go unit tests
asserting the exact hex output. If you can compute the actual Blake2b-256 hex digest for these
two known input byte-sequences and it matches what the Rust `assert_eq!` would produce (it must,
since the byte sequence being hashed is now fully pinned down above), that IS a byte-exact
verified primitive, no Rust toolchain needed for this specific piece — the "known good" fixture
already exists in Tari's own repo.

## 2. `CommsCoreHashDomain` (source: `tari/comms/core/src/types.rs`)

```rust
hash_domain!(CommsCoreHashDomain, "com.tari.comms.core", 0);
```
domain = `"com.tari.comms.core"`, version = `0` (NOT the macro's 2-arg default of 1 — this one
explicitly passes version 0). So for label `"noise.dh"`:
tag = `"com.tari.comms.core.v0.noise.dh"`.

## 3. Noise DH → KDF (source: `tari/comms/core/src/noise/crypto_resolver.rs`)

```rust
type TariCommsNoiseHasher = DomainSeparatedHasher<Blake2b<U32>, CommsCoreHashDomain>;

fn noise_kdf(shared_key: &CommsDHKE) -> CommsNoiseKey {
    TariCommsNoiseHasher::new_with_label("noise.dh")
        .chain(shared_key.as_bytes())
        .finalize_into(...) // 32 bytes output
}

impl Dh for CommsDiffieHellman {
    fn name(&self) -> &'static str { "Ristretto" }
    fn pub_len(&self) -> usize { 32 }
    fn priv_len(&self) -> usize { 32 }
    fn dh(&self, public_key: &[u8], out: &mut [u8]) -> Result<(), snow::Error> {
        let pk = UncompressedCommsPublicKey::from_canonical_bytes(&public_key[..32])?; // RistrettoPublicKey
        let shared = CommsDHKE::new(&self.secret_key, &pk); // shared = secret_key * pk  (standard Ristretto255 scalar mult)
        let hash = noise_kdf(&shared);                      // domain-separated Blake2b-256 KDF, see above
        out.copy_from_slice(hash.reveal());                 // 32 bytes fed to snow as the "DH output"
        Ok(())
    }
}
```

`CommsDHKE = DiffieHellmanSharedSecret<RistrettoPublicKey>`, and
`DiffieHellmanSharedSecret::new(sk, pk) = sk * pk` (source: `tari-crypto/src/dhke.rs`) — this is
literally `secret_scalar * peer_point`, a standard Ristretto255 scalar multiplication, no extra
cofactor/clamping tricks. `.as_bytes()` on the result is the canonical 32-byte Ristretto255 point
encoding of that shared point (standard Ristretto255 compressed point, same encoding
`gtank/ristretto255`'s `Element.Encode`/`Decode` uses — verify this claim by checking that
package's own doc/tests once added as a dependency, since it wraps `filippo.io/edwards25519`
which implements the canonical Ristretto255 spec, RFC 9496 / Ristretto draft).

**Go implementation plan**: implement a Go type satisfying `flynn/noise`'s `noise.DHFunc`
interface (`GenerateKeypair(io.Reader) (DHKey, error)`, `DH(priv, pub []byte) ([]byte, error)`,
`DHLen() int`, `DHName() string`) called e.g. `RistrettoDH`:
- `GenerateKeypair`: sample a uniformly random Ristretto255 scalar (32 bytes; use
  `ristretto255.NewScalar().Rand(rng)` or equivalent from `gtank/ristretto255`, confirm exact API
  via that package's actual source/docs before use — DO NOT guess method names), derive the
  public point = scalar * Ristretto255 basepoint, encode both canonically (32 bytes each).
- `DH(priv, pub)`: decode `priv` as a Ristretto255 scalar, decode `pub` as a Ristretto255
  element/point (reject if decode fails — canonical-encoding check, matches Rust's
  `from_canonical_bytes` which errors on non-canonical input), compute `shared = priv * pub`
  (scalar-point multiply), canonically encode the resulting point to 32 bytes, then run those 32
  bytes through the domain-separated Blake2b-256 KDF from section 1+2+3 above (label
  `"noise.dh"`, domain `CommsCoreHashDomain`), and return that 32-byte KDF output as the DH
  result (this is what gets fed into snow's / flynn-noise's internal chaining-key mixing — NOT
  the raw DH point).
- `DHLen()` returns 32.
- `DHName()` — the Tari Rust side names this DH function `"Ristretto"` inside the resolver
  (which snow parses/labels internally), but note the *protocol name string* Tari parses is
  literally `"Noise_XX_25519_ChaChaPoly_BLAKE2b"` (source: `comms/core/src/noise/config.rs`
  constant `NOISE_PARAMETERS`) — i.e. Tari deliberately reuses the "25519" slot in the Noise
  protocol name string even though the actual DH plugged in via the custom `CryptoResolver` is
  Ristretto255, not X25519. For interop with `flynn/noise`'s `NewCipherSuite(dh, cipher, hash)`
  (which builds its own name string as `dh.DHName()+"_"+cipher.CipherName()+"_"+hash.HashName()`),
  set `DHName()` to return `"25519"` so the resulting suite name string is literally
  `"25519_ChaChaPoly_BLAKE2b"` — matching what Tari's protocol name implies for the non-DH-name
  parts, and documented in a comment explaining this deliberate naming quirk mirrors Tari's own
  wire-format constant. This name string is NOT sent over the wire by either side in the actual
  XX handshake bytes (Noise protocol names aren't transmitted, only implicit via prologue +
  matching primitive choices) so an exact string match with Tari's Rust side isn't required for
  interop — cipher/hash/pattern/prologue/actual DH math are what must match byte-for-byte. State
  this clearly in a comment so nobody "fixes" the name string later thinking it's load-bearing.

## 4. Cipher / Hash for flynn/noise

- Cipher: `noise.CipherChaChaPoly` (flynn/noise built-in, standard ChaCha20-Poly1305, verify
  exact identifier via that package's `cipher_suite.go`).
- Hash: `noise.HashBLAKE2b` (flynn/noise built-in, BLAKE2b-512 per its own `cipher_suite.go`
  source — this is the handshake-hash function used for `h`/chaining-key mixing internally by
  Noise, a *different* Blake2b usage from the DH-output KDF in section 3, don't conflate them).
- Pattern: `noise.HandshakeXX`.
- Initiator: we are always the initiator (dialing out).
- Prologue: exact byte string `[]byte("com.tari.comms.noise.prologue")` (source:
  `comms/core/src/noise/config.rs` constant `TARI_PROLOGUE` — confirmed exact literal, no null
  terminator, ASCII).
- Build with `noise.NewHandshakeState(noise.Config{...})`: pass `CipherSuite:
  noise.NewCipherSuite(yourRistrettoDH, noise.CipherChaChaPoly, noise.HashBLAKE2b)`, `Pattern:
  noise.HandshakeXX`, `Initiator: true`, `Prologue: tariPrologue`, `StaticKeypair:
  <our Ristretto keypair as noise.DHKey{Private, Public}>`.
- 3-message flow for initiator: `WriteMessage` (msg1, `-> e`), then read peer's msg2 response
  (`ReadMessage`, `<- e, ee, s, es` — this call returns the peer's recovered static public key via
  `HandshakeState.PeerStatic()` after this step), then `WriteMessage` (msg3, `-> s, se`) which on
  flynn/noise's API typically returns the two `*noise.CipherState` (tx/rx) once the handshake
  completes (check exact return signature/method name in flynn/noise source, likely
  `WriteMessage`/`ReadMessage` returning `(out []byte, cs1, cs2 *CipherState, err error)` on the
  final message — confirm precisely, don't guess).
- Recover the peer's static public key (32-byte Ristretto255 point encoding) via
  `HandshakeState.PeerStatic()` after the handshake completes — this is the peer's real Tari
  node identity key material.

## 5. Wire framing

### 5a. Network wire byte (source: `comms/core/src/protocol/network_info.rs`,
`NodeNetworkInfo.network_wire_byte`, default `0x00`)
Immediately after TCP connect, BEFORE any Noise bytes, the dialing/outbound side writes exactly
one byte: `0x00`. (Reserved value `0xa7` = `LIVENESS_WIRE_MODE`, source:
`comms/core/src/connection_manager/wire_mode.rs` — NOT used here, just documented as a
comment for context; do not implement liveness mode.)

### 5b. Post-handshake transport frames (source: `comms/core/src/noise/socket.rs`)
`MAX_PAYLOAD_LENGTH = 65535` (`u16::MAX`). Each frame: `u16 BIG-ENDIAN` length prefix, followed
by that many bytes of Noise-transport ciphertext (one `CipherState.Encrypt`/flynn-noise
equivalent call per frame — i.e. one Noise transport message per frame, NOT a raw stream
cipher). A frame length of `0` is legal (empty frame, socket.rs handles it as a no-op read case)
but you don't need to replicate that edge case for a health-check client — documented as a
known simplification if you skip it.

### 5c. Identity protocol frame (source: `comms/core/src/protocol/identity.rs`,
`write_protocol_frame`/`read_protocol_frame`) — this nests INSIDE a single 5b transport frame's
plaintext (i.e.: encrypt this whole byte sequence as one Noise transport message, then wrap
THAT in a 5b u16-BE-length-prefixed frame):
```
[1 byte version][2 bytes LE(u16) message length][protobuf PeerIdentityMsg bytes]
```
`version` = `major_version` (a single `u8`, NOT multiple version bytes — Tari's
`NodeNetworkInfo.major_version` defaults to `0` via `#[derive(Default)]`, send `0`). The 2-byte
length is `u16::to_le_bytes()`/`from_le_bytes()` — **little-endian**, deliberately different
endianness from the OUTER 5b frame's big-endian length prefix; don't accidentally reuse the same
helper for both. `MAX_IDENTITY_PROTOCOL_MSG_SIZE = 1024` — reject/error if a received message's
declared length exceeds 1024 (protocol violation / hostile peer). 10-second read timeout via
`context.WithTimeout` / equivalent.

Both sides send immediately (half-RTT: write yours, THEN read theirs — not request/response),
matching Tari's own doc comment:
```
[initiator]   (simultaneous)   [responder]
  |  ---------[identity]--------> |
  |  <---------[identity]-------- |
```

## 6. `PeerIdentityMsg` protobuf (verbatim schema, package `tari.comms.identity`)

```protobuf
syntax = "proto3";
package tari.comms.identity;

message PeerIdentityMsg {
    repeated bytes addresses = 1;
    uint32 features = 2;
    repeated bytes supported_protocols = 3;
    string user_agent = 4;
    IdentitySignature identity_signature = 5;
}

message IdentitySignature {
    uint32 version = 1;
    bytes signature = 2;
    bytes public_nonce = 3;
    int64 updated_at = 4;
}
```
Vendor this `.proto` file into `p2p/proto/identity.proto` and generate Go bindings with
`protoc` (available on PATH — confirm with `protoc --version`) + the standard
`protoc-gen-go` plugin, consistent with how `go-tari-grpc-lib` generates its protos elsewhere in
this ecosystem (check that repo's generation convention if reachable, otherwise use the standard
`protoc --go_out=. --go_opt=paths=source_relative identity.proto` invocation, `go_package` option
set to this new package's proto subpackage path). Install `protoc-gen-go` via
`go install google.golang.org/protobuf/cmd/protoc-gen-go@latest` if not already on PATH — verify
with `which protoc-gen-go` first.

Our OUTGOING `PeerIdentityMsg` (minimal, don't fabricate a real node identity):
- `addresses`: empty
- `features`: `0`
- `supported_protocols`: empty
- `user_agent`: `"go-tari-lib-p2p-probe/0.1"`
- `identity_signature`: `nil` (omit — this is a deliberate simplification; if a live peer
  rejects/bans us for missing it, that's a real finding to surface in error messages, not
  something to work around by fabricating a signature)

Fully parse and surface whatever the PEER sends back (their addresses, features,
supported_protocols, user_agent, identity_signature fields) in the returned Go struct.

## 7. Package API to build

```go
package p2p

// PeerInfo is the result of a successful P2P probe.
type PeerInfo struct {
    Reachable         bool
    RemoteStaticPubKey []byte // 32-byte canonical Ristretto255 public key
    Addresses          [][]byte
    Features           uint32
    SupportedProtocols [][]byte
    UserAgent          string
    IdentitySignature  *IdentitySignature // nil if peer didn't send one
    Latency            time.Duration
}

type IdentitySignature struct {
    Version     uint32
    Signature   []byte
    PublicNonce []byte
    UpdatedAt   int64
}

// Probe dials addr (host:port), performs wire-byte + Noise_XX handshake + identity exchange,
// and returns peer info. Returns a clean error (not panic) for unreachable/non-Tari peers.
func Probe(ctx context.Context, addr string) (*PeerInfo, error)
```

Also needed, as internal building blocks reusable by other go-tari-* consumers later (export
them, don't bury as unexported):
- `type RistrettoDH struct{}` implementing `noise.DHFunc` (section 3).
- `GenerateRistrettoKeypair() (noise.DHKey, error)` convenience wrapper.
- `func InitiatorHandshake(ctx context.Context, conn net.Conn, staticKeypair noise.DHKey) (*Session, error)`
  — writes wire byte, runs the 3-message Noise_XX exchange as initiator, wraps the resulting
  cipher states + peer static pubkey in a `Session`.
- `type Session struct { ... }` wrapping the post-handshake `net.Conn` + tx/rx `*noise.CipherState`
  + `PeerStaticKey []byte`, with methods to send/receive length-prefixed encrypted frames
  (section 5b) and a method `ExchangeIdentity(ctx context.Context) (*PeerIdentityMsg, error)`
  (section 5c/6) built on top of the frame methods.
- A minimal **responder**-side counterpart (`ResponderHandshake`, same shape but
  `Initiator: false`) — ONLY as much as needed to test the initiator against something real in
  an in-process test; do not build out a full listener/server abstraction beyond that.

## 8. Testing

1. **Domain-separated hasher unit tests** — hard-code the two real Rust test vectors from
   section 1 and assert byte-exact match. Also test the `CommsCoreHashDomain`/`"noise.dh"` tag
   construction directly (`"com.tari.comms.core.v0.noise.dh"`, len 32) as its own assertion even
   though we don't have a full end-to-end Rust DH vector for it — comment clearly: "tag
   construction reuses the byte-exact-verified generic hasher above; the DH математика
   (scalar/point encoding) itself is NOT independently cross-verified against a real Rust
   `tari_crypto` run in this environment — no cargo/rustc available, crates.io unreachable from
   this sandbox on 2026-08-17."
2. **Ristretto255 primitive sanity** — round-trip: generate keypair, encode/decode, confirm
   scalar-mult DH agreement between two independently generated keypairs (`A_priv * B_pub ==
   B_priv * A_pub`, standard DH symmetry) BEFORE the KDF is applied, i.e. test the raw DH
   agreement and the post-KDF agreement as two separate assertions.
3. **In-process two-peer Noise_XX + identity exchange test** using `net.Pipe()` (or loopback TCP
   if `net.Pipe` proves awkward with the framing code — your call, document which you used and
   why): one goroutine as initiator, one as responder, both using your real
   `RistrettoDH`/handshake code. Assert: handshake completes on both sides without error, each
   side's recovered peer static pubkey matches the other side's actual static public key bytes,
   `ExchangeIdentity` on both sides completes and each side correctly decodes the other's
   `user_agent`/`features`/etc.
4. `go build ./...`, `go vet ./...`, `gofmt -l .` (must be empty), `go test ./...`,
   `go mod tidy` — all clean, per this repo's `AGENTS.md`.
5. Do NOT attempt a live network probe against a real mainnet Tari node from this sandbox as
   part of the automated test suite (no guaranteed reachable target, would make tests flaky/
   network-dependent) — `Probe()`'s correctness is validated by the in-process test in point 3
   using the exact same code path (dial replaced by an in-memory pipe).

## 9. Commit

Single or a few logical commits on the current branch (`feat/p2p-noise-handshake`, already
checked out) using Conventional Commits (e.g. `feat(p2p): add Tari Noise_XX P2P handshake client`).
Do NOT push, do NOT touch `main`, do NOT touch `nodeGRPC/`/`walletGRPC/`.

## 10. What NOT to build

- No RPC-over-P2P protocol (comms/core/src/protocol/rpc/*) — out of scope.
- No full peer-management/address-book logic — this is a single-shot client probe only.
- No liveness-wire-mode (0xa7) support — always send 0x00.

## Final report requirement

At the end, write a short `p2p/VERIFICATION.md` summarizing exactly what was byte-exact
verified against real Tari Rust source/test-vectors vs. what is Go-only-internally-consistent
and NOT independently cross-checked (be specific: name the exact primitive, e.g. "Ristretto255
scalar-point multiplication correctness relies on gtank/ristretto255's own test suite, not a
side-by-side Rust comparison, because no Rust toolchain was available in this sandbox").
