# VERIFICATION.md

This document summarizes, per primitive, what in this package's implementation of the Tari P2P
(`tari_comms`) Noise_XX handshake client was **byte-exact verified against real Tari Rust
source/test-vectors**, versus what is **Go-only, internally-consistent, and NOT independently
cross-verified** against a real Rust run.

Context: this package was originally written in a sandbox with no `cargo`/`rustc` available and
no access to crates.io (403) as of 2026-08-17, so no Rust code could be compiled or run to
generate fresh test vectors. However, outbound HTTPS access to `raw.githubusercontent.com` (and
the Go module proxy) *was* available, so the actual Tari and tari-crypto Rust source files were
fetched and read directly (not just relied on from the pre-existing prose description in
`P2P_SPEC.md`) to confirm every wire-format and cryptographic detail below against the real
`development` branch of `github.com/tari-project/tari` and `main` branch of
`github.com/tari-project/tari-crypto`.

## Byte-exact verified against real Tari Rust source / test vectors

- **Domain-separated hasher construction and both test vectors**
  (`p2p/hashing.go`, `p2p/hashing_test.go`). The exact byte sequence hashed by
  `TestDeconstructionVector` and `TestDomainSeparationTagHashingVector` is transcribed verbatim
  from `tari-crypto/src/hashing.rs`'s own `#[test] fn deconstruction()` and
  `#[test] fn domain_separation_tag_hashing()` (confirmed by fetching that file directly from
  `raw.githubusercontent.com/tari-project/tari-crypto/main/src/hashing.rs`). Because Blake2b-256
  is a standard, deterministic, cross-language-identical algorithm (RFC 7693), computing it in Go
  (via `golang.org/x/crypto/blake2b`) over that exact, fully-pinned byte sequence is equivalent to
  it having been computed by the real Rust code -- no Rust toolchain is needed to make this claim
  for *this specific primitive*, because the "known good" fixture already existed in Tari's own
  repository and the byte sequence it hashes is unambiguous.
- **`CommsCoreHashDomain` domain string and version** (`"com.tari.comms.core"`, version `0`,
  *not* the `hash_domain!` macro's 2-arg default of `1`) -- confirmed by fetching
  `tari/comms/core/src/types.rs`.
- **`noise.dh` KDF label and construction** (`TariCommsNoiseHasher::new_with_label("noise.dh")`,
  `.chain(shared_key.as_bytes())`) -- confirmed by fetching
  `tari/comms/core/src/noise/crypto_resolver.rs`.
- **`DiffieHellmanSharedSecret::new(sk, pk) = sk * pk`** (standard Ristretto255 scalar-point
  multiplication, no cofactor/clamping) -- confirmed by fetching `tari-crypto/src/dhke.rs`.
- **Noise protocol parameters**: pattern `XX`, DH slot `Curve25519`-named-but-Ristretto255,
  cipher `ChaChaPoly`, hash `Blake2b`, protocol name string
  `"Noise_XX_25519_ChaChaPoly_BLAKE2b"` -- confirmed by fetching
  `tari/comms/core/src/noise/config.rs` (including its own `check_noise_params` unit test, which
  asserts each of `DHChoice::Curve25519`/`CipherChoice::ChaChaPoly`/`HashChoice::Blake2b`/
  `HandshakePattern::XX` against the parsed `NOISE_PARAMETERS` constant).
- **Noise prologue**: exact literal `b"com.tari.comms.noise.prologue"`, no null terminator --
  confirmed by fetching `tari/comms/core/src/noise/config.rs` (`NoiseConfig::upgrade_socket`'s
  local `TARI_PROLOGUE` constant).
- **Network wire byte**: `0x00` default, sent once immediately after TCP connect, before any
  Noise bytes -- confirmed by fetching `tari/comms/core/src/protocol/network_info.rs`
  (`NodeNetworkInfo`, `#[derive(Default)]`).
- **Liveness wire mode reserved value**: `0xa7` -- confirmed by fetching
  `tari/comms/core/src/connection_manager/wire_mode.rs`. Documented for context only; not
  implemented (P2P_SPEC.md section 10).
- **Wire framing applies to Noise handshake messages, not just post-handshake transport
  data.** This is a **correction of the literal wording** in `P2P_SPEC.md` section 5b (which
  titled that framing description "Post-handshake transport frames"). Fetching the real
  `tari/comms/core/src/noise/socket.rs` and tracing `Handshake::handshake_1_5rtt` ->
  `Handshake::send`/`receive` -> `NoiseSocket::poll_write_or_flush`/`poll_read` shows the exact
  same `u16`-big-endian length-prefix-then-payload framing (`WriteState::WriteFrameLen` /
  `ReadState::ReadFrameLen`) is used uniformly for **every** write/read through a `NoiseSocket`,
  during the handshake phase (`state: NoiseState::HandshakeState`) exactly as much as afterwards
  (`state: NoiseState::TransportState`) -- it's the same state machine either way, only the inner
  `state.write_message`/`read_message` call's target (`HandshakeState` vs `TransportState`)
  differs. `p2p/frame.go`'s `writeFrame`/`readFrame` are used for both the three Noise_XX
  handshake messages (`p2p/handshake.go`) and post-handshake transport frames
  (`p2p/session.go`), matching this real behaviour rather than the more literal (and, on
  inspection, incomplete) section-5b-only reading of the spec prose.
- **`MAX_PAYLOAD_LENGTH = 65535` (`u16::MAX`)** -- confirmed via the same `socket.rs` fetch.
- **Identity protocol frame layout**: `[1 byte version][2 bytes LE(u16) length][protobuf
  bytes]`, `MAX_IDENTITY_PROTOCOL_MSG_SIZE = 1024`, 10-second read timeout, half-RTT
  write-then-read-yours-then-theirs on both sides -- confirmed by fetching
  `tari/comms/core/src/protocol/identity.rs` directly (`write_protocol_frame`,
  `read_protocol_frame`, `identity_exchange`).
- **`PeerIdentityMsg`/`IdentitySignature` protobuf schema** (`p2p/proto/identity.proto`) --
  field names, numbers and types transcribed verbatim from `P2P_SPEC.md` section 6, which itself
  was extracted from the real Tari `.proto` source; not independently re-fetched from
  `tari/comms/core/src/proto/identity.proto` in this pass (P2P_SPEC.md's transcription was
  trusted as-is for this one file, since it's a simple, mechanically-checkable protobuf schema
  with no subtle byte-layout semantics the way the framing/crypto primitives above have).

## Go-only, internally consistent, NOT independently cross-verified against a real Rust run

- **Ristretto255 scalar/point arithmetic correctness itself** (`p2p/ristretto_dh.go`): canonical
  encode/decode, scalar-point multiplication, and the "random uniform scalar via 64 random bytes
  reduced mod the group order" keypair generation approach all rely entirely on
  `github.com/gtank/ristretto255`'s own implementation and test suite (which implements RFC
  9496), not on a side-by-side comparison against a real `tari_crypto`/`curve25519-dalek-ng` Rust
  run. `TestRistrettoDHAgreement` and `TestRistrettoKeypairRoundTrip`
  (`p2p/ristretto_dh_test.go`) are Go-only round-trip/symmetry checks (`A_priv*B_pub ==
  B_priv*A_pub`, `pub == priv*basepoint`), not comparisons against a known Rust-computed value.
- **The *value* of `noiseDHKDF`'s output for any given real Ristretto255 shared secret.** The
  tag construction (`"com.tari.comms.core.v0.noise.dh"`) and length-prefix framing algorithm it's
  built on are byte-exact verified (see above); what is NOT verified is that this Go
  implementation, given the *same* Ristretto255 private/public keys as a real
  `tari_crypto`/`comms/core` Rust node, would compute the *same* 32-byte KDF output. That would
  require either a Rust toolchain (unavailable) or a live interop test against a real Tari peer
  (explicitly out of scope for the automated test suite per P2P_SPEC.md section 8 point 5).
- **`RistrettoDH.DHName()` returning `"25519"` instead of `"Ristretto"`** is a deliberate,
  documented design choice (see the doc comment on `RistrettoDH` in `p2p/ristretto_dh.go`), not a
  Rust-source-verified value in the sense of "Tari's Rust code also calls it this" -- Tari's own
  `Dh::name()` impl returns `"Ristretto"`. This Go package's choice of `"25519"` only affects the
  cosmetic `noise.CipherSuite.Name()` string inside `flynn/noise`, which (per the Noise
  specification) is never transmitted over the wire during the XX handshake, so it cannot affect
  interop either way.
- **The full end-to-end handshake + identity exchange interop with a real, live Tari node.**
  This package has not been run against any real Tari base node, wallet, or other `tari_comms`
  peer -- per P2P_SPEC.md section 8 point 5, the automated test suite deliberately avoids a live
  network probe (no guaranteed reachable target, flaky/network-dependent). Confidence that the
  handshake and identity exchange logic here would work against a real peer rests entirely on:
  (a) the byte-exact-verified primitives listed above, and (b) `p2p_test.go`'s in-process
  initiator/responder test, which exercises the *exact same* `InitiatorHandshake`/
  `ResponderHandshake`/`Session`/`ExchangeIdentity` code paths against each other over both
  `net.Pipe()` and a real loopback TCP connection (via `Probe()`), but both ends of that test are
  this package's own code, not a real Tari Rust node.
- **`ResponderHandshake`'s handling of "liveness wire mode" (`0xa7`)**: it detects and rejects
  that byte with a clear error rather than actually implementing liveness mode (correctly out of
  scope per P2P_SPEC.md section 10), but this rejection path itself has no real Tari liveness-mode
  peer to test against.
- **The zero-length-frame-is-a-no-op-and-keep-reading edge case** documented in `socket.rs`
  (`ReadState::ReadFrameLen` treating a `frame_len == 0` as a transition back to `ReadState::Init`
  rather than a payload) is explicitly NOT replicated by `p2p/frame.go`'s `readFrame`, which
  returns an empty (non-nil) payload for a zero-length frame instead. This is a documented
  simplification (per P2P_SPEC.md section 5b) rather than an oversight; it is not expected to be
  exercised given the fixed, always-non-empty message shapes this client sends/expects.
