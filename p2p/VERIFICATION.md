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

## Part A/B addendum (2026-08-17): RPC-over-P2P get_chain_metadata + SOCKS5/.onion dialing

This section documents what was added on top of the above (`p2p/rpc/*`,
`p2p/chainmetadata_probe.go`, `p2p/socks.go`), using the same
byte-exact-verified-vs-Go-only-internally-consistent disclosure pattern as the rest of this
document. The originating scratch spec for this pass (`p2p/RPC_TOR_SPEC.md`) was deleted after
landing this work -- it was a working document, not meant to ship; everything load-bearing from
it is captured here and in the code's own doc comments.

### Byte-exact verified against real Tari Rust source

- **Protocol-negotiation-frame-vs-canonical-frame nesting** (the one genuinely ambiguous point
  going into this pass): protocol negotiation frames (`p2p/rpc/negotiation.go`) are sent as the
  raw plaintext of a single Noise transport message (i.e. passed directly to this package's
  existing `Session.SendFrame`/returned directly from `Session.ReceiveFrame`, with NO u32
  canonical-frame wrapper), whereas the RPC session handshake and RPC request/response messages
  (`p2p/rpc/handshake.go`, `p2p/rpc/chainmetadata.go`) ARE wrapped in a u32-BE
  length-delimited "canonical frame" (`p2p/rpc/canonicalframe.go`) before being handed to
  `Session.SendFrame`/read back from `Session.ReceiveFrame`. This was traced through, and is
  byte-exact verified against, real fetched Tari source:
  `comms/core/src/protocol/negotiation.rs` (`ProtocolNegotiation::new` constructed directly on
  the raw `NoiseSocket`, `read_frame`/`write_frame_flush` calling `socket.read_exact`/`write_all`
  directly -- no `CanonicalFraming`/`LengthDelimitedCodec` involved), `comms/core/src/framing.rs`
  (`framing::canonical` = `tokio_util::codec::LengthDelimitedCodec` with default
  big-endian/u32 length-field settings, applied only AFTER negotiation succeeds), and
  `comms/core/src/protocol/rpc/handshake.rs` (`Handshake::new(framed: &mut CanonicalFraming<T>)`,
  confirming the handshake/request/response layer is the canonical-framed one).
- **Protocol negotiation frame layout** `[len (1 byte u8)][flags (1 byte)][protocol id (up to
  255 bytes)]`, the `NONE`/`OPTIMISTIC`/`TERMINATE`/`NOT_SUPPORTED` flag bits, and the
  non-optimistic outbound negotiation flow (write once, read once, check flags, else compare the
  echoed protocol id byte-exact) -- confirmed via `comms/core/src/protocol/negotiation.rs`.
- **RPC session handshake** message flow and `RpcSession`/`RpcSessionReply` shape (including the
  `accepted_version`/`rejected` oneof and `HandshakeRejectReason` enum) -- confirmed via
  `comms/core/src/protocol/rpc/handshake.rs` (`perform_client_handshake`).
- **`t/blksync/1` protocol id string** (`[]byte("t/blksync/1")`, 11 bytes, no NUL terminator) --
  confirmed via `#[tari_rpc(protocol_name = b"t/blksync/1", ...)]` on the `BaseNodeSyncService`
  trait, `base_layer/core/src/base_node/sync/rpc/mod.rs`.
- **get_chain_metadata method number `5`** -- confirmed via `#[rpc(method = 5)] async fn
  get_chain_metadata` on the same trait (method numbers there are explicit per-method
  attributes -- 1,2,3,4,6,8 are the other methods present, with no method 7, ruling out a
  sequential/inferred numbering scheme).
- **`ChainMetadata` protobuf field names/numbers/types** (`best_block_height=1`,
  `best_block_hash=2`, `accumulated_difficulty_low=5`, `accumulated_difficulty_high=8`,
  `pruned_height=6`, `timestamp=7`) -- confirmed via
  `base_layer/core/src/base_node/proto/chain_metadata.proto`. The real file's unused
  `import "google/protobuf/wrappers.proto";` (dead even in the real file -- no field actually
  uses a wrapper type) is deliberately omitted from `p2p/proto/chain_metadata.proto`.
- **`RpcRequest`/`RpcResponse` protobuf shape** (`request_id`, `method`, `flags`, `deadline`,
  `payload` on the request; `request_id`, `status`, `flags`, `payload` on the response) --
  confirmed via `comms/core/src/proto/rpc.proto`.
- **SOCKS5/.onion dialing is a bog-standard SOCKS5 proxy dial, no Tari-specific extension** --
  confirmed via `comms/core/src/transports/socks.rs`.

### Go-only, internally consistent, NOT independently cross-verified against a real Rust run

- **`p2p/proto/rpc.pb.go` and `p2p/proto/chain_metadata.pb.go`** were generated with `protoc
  --go_out=. --go_opt=paths=source_relative` against protoc v29.1 / protoc-gen-go v1.36.12 in
  this sandbox -- the same protoc-gen-go version already recorded in the header comment of the
  pre-existing `p2p/proto/identity.pb.go` (protoc-gen-go v1.36.12), so generated-code style/
  package layout is consistent across all three `.proto` files in this repo.
- **The full RPC-over-P2P flow (negotiation -> session handshake -> get_chain_metadata request/
  response) end to end against a real, live Tari base node.** This has NOT been exercised in
  this sandbox (no reachable target / out of scope for this pass, matching the same limitation
  already documented above for the Noise_XX handshake + identity exchange). Confidence rests on:
  (a) the byte-exact-verified wire-format primitives listed above, and (b) `p2p/rpc`'s in-process
  responder tests (`p2p/rpc/rpc_test.go`,
  `p2p/rpc/negotiation_handshake_external_test.go`), which exercise the exact same
  `NegotiateProtocol`/`PerformSessionHandshake`/`GetChainMetadata` client code paths against a
  responder built from this package's own `NegotiateProtocolInbound`/
  `PerformSessionHandshakeResponder`/`RejectSessionHandshakeResponder` helpers over a real
  Noise_XX-handshaked `Session` pair (`net.Pipe()` + `InitiatorHandshake`/`ResponderHandshake`) --
  covering the happy path, the negotiation NOT_SUPPORTED path, the RPC-handshake-rejected path,
  and the RpcResponse.status-non-zero path -- but both ends of those tests are this package's own
  code, not a real Tari Rust node.
- **The value of a real peer's `RpcResponse.status` error-payload encoding** for a non-zero
  status: per p2p/RPC_TOR_SPEC.md section A3 this was explicitly out of scope to specify/decode
  (`GetChainMetadata` surfaces only the raw status code via `*rpc.RPCStatusError` and does not
  attempt to decode `payload` in that case), so there is nothing to verify here beyond "the raw
  uint32 status field is surfaced faithfully."
- **`golang.org/x/net/proxy`'s own SOCKS5 client implementation correctness** (RFC 1928/1929
  handshake bytes on the wire) is relied on as-is; not independently re-verified byte-by-byte in
  this pass, since it's a well-established, widely used part of the Go standard extended library
  rather than Tari-specific code.
- **A real, end-to-end `.onion` dial through an actual Tor daemon.** This is explicitly NOT
  verified -- no Tor daemon is available in this sandbox. `p2p/socks_test.go` verifies: (1) a
  `.onion` address with no `SocksProxyAddr` configured returns the specific
  onion-requires-a-proxy error rather than a generic timeout/DNS error; (2) a `.onion` address
  WITH a `SocksProxyAddr` configured actually attempts to go through that proxy address (proven
  against a real local TCP listener standing in for "the SOCKS proxy" -- the SOCKS5 handshake
  itself is expected to fail against that non-SOCKS listener, which is the point: it proves the
  code reached and spoke to the configured proxy rather than trying to resolve the `.onion`
  hostname via DNS); and (3) a non-`.onion` address with a SocksProxyAddr configured anyway still
  dials directly, bypassing the proxy entirely (proven against a real loopback listener while
  pointing SocksProxyAddr at a reserved-then-closed, guaranteed-unreachable port). None of these
  three tests involve a real Tor daemon or a real onion-service peer -- that remains a documented
  gap, to be verified independently, out of scope for this sandbox.
- **`p2p.ProbeChainMetadata`** (`p2p/chainmetadata_probe.go`) is a thin composition of
  `InitiatorHandshake` (already covered above) and `p2p/rpc.GetChainMetadata` (covered above) --
  it introduces no new wire-format details of its own, so its correctness rests entirely on the
  two pieces it composes; it has no dedicated live-network test in this package's own suite for
  the same "no guaranteed reachable target" reason `Probe` itself doesn't.
