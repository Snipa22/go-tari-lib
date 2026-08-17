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

## Part C addendum (2026-08-17): fix -- RPC-over-P2P was missing the Yamux multiplexing layer

### The bug (confirmed against 2 real Tari mainnet nodes)

Everything documented in the "Part A/B addendum" section above was internally self-consistent
(this package's own client talking to this package's own in-process fake responder), but was
**wrong when run against real Tari mainnet nodes**. The failure, confirmed live against two
separate real nodes:

```
rpc: negotiation frame declares protocol id length 0 but 229 bytes follow the header
```

i.e. `decodeNegotiationFrame` (`p2p/rpc/negotiation.go`) received a `ReceiveFrame()` payload
whose first byte (the declared protocol-id length) was `0`, but which actually had 229 more
bytes tacked on after that -- garbage from this client's point of view, but not actually garbage:
it was the real node's own Yamux framing bytes, which this client had never established a Yamux
session over and therefore could not parse.

### Root cause

Root cause, confirmed by fetching and reading the real Tari Rust source directly:

- `comms/core/src/connection_manager/peer_connection.rs`: once the Noise_XX handshake completes,
  every real Tari node immediately establishes a Yamux multiplexed session
  (`yamux::Connection::new`) on top of the Noise transport, and ALL subsequent protocol
  negotiation and RPC traffic runs on Yamux SUBSTREAMS opened over that session -- never directly
  on the raw post-handshake Noise transport.
- `comms/core/src/multiplexing/yamux.rs`: confirms the Yamux session is layered directly on top
  of the (already-encrypted) Noise socket -- i.e. Yamux's own multiplexed byte stream is the
  PLAINTEXT PAYLOAD of Noise transport frames, not a replacement for the Noise transport framing.

This client's `p2p/rpc` package (protocol negotiation, the RPC session handshake, and
`get_chain_metadata`) was wired directly onto `*p2p.Session`'s raw `SendFrame`/`ReceiveFrame`
(one Noise transport frame per protocol message, no Yamux in between at all). Every wire-format
detail listed as "byte-exact verified" in the Part A/B addendum above (negotiation frame layout,
canonical frame layout, protobuf shapes, protocol id, method number, etc.) was and remains
correct -- the bug was purely a missing intermediate layer, not an error in any of those
primitives. A real node, expecting Yamux-framed bytes on the substream, saw this client's raw
negotiation-frame bytes arrive as if they were Yamux protocol bytes (or vice versa, depending on
which side's framing got desynced first), producing the nonsensical-looking length declaration
above.

### The fix

Correct layering, now implemented:

```
Noise transport (u16 BE frames, p2p.Session.SendFrame/ReceiveFrame)
  -> Yamux multiplexed connection/substream (github.com/hashicorp/yamux)
    -> Canonical RPC framing (u32 BE length prefix, p2p/rpc/canonicalframe.go) INSIDE that substream
      -> protobuf payloads
```

Concretely:

- **`p2p/yamuxadapter.go`** (new): `sessionReadWriteCloser` adapts `*p2p.Session`'s frame-oriented
  `SendFrame`/`ReceiveFrame` to the plain `io.ReadWriteCloser` interface `yamux.Client`/
  `yamux.Server` require as their underlying transport -- one `Write` call becomes one
  `SendFrame` call (one Noise transport frame), and `Read` drains/buffers across
  `ReceiveFrame` calls as needed, since a caller's `Read` buffer (yamux's own internal reader, in
  practice) is not guaranteed to be sized to match a whole Noise transport frame.
- **`p2p/rpc/streamtransport.go`** (new): `streamTransport`/`NewStreamTransport` implement
  `rpc.Transport` (`SendFrame`/`ReceiveFrame`, one complete message per call) directly on top of
  a raw `io.ReadWriteCloser` byte stream -- i.e. a Yamux substream (a `net.Conn`).
  - **Framing decision (corrected -- see "Correction" subsection immediately below for the
    mistake this replaces):** `streamTransport` adds **ZERO extra framing of its own**. Both
    message kinds that flow over it are already fully self-delimiting on their own, and
    `SendFrame` writes whatever payload it's given straight to the stream, byte-for-byte,
    unmodified:
    - Protocol negotiation frames (`negotiation.go`'s `encodeNegotiationFrame`/
      `decodeNegotiationFrame`): `[1-byte length][1-byte flags][protocol id, `length` bytes]`.
      Confirmed byte-for-byte against real Tari's `comms/core/src/protocol/negotiation.rs`:
      `write_frame_flush`/`read_frame` operate directly on the raw socket with no outer wrapper
      around this 2-byte-header-plus-body message at all.
    - Canonical RPC frames (`canonicalframe.go`'s `EncodeCanonicalFrame`/`DecodeCanonicalFrame`):
      `[4-byte u32-BE length][payload, `length` bytes]`. This is already the exact wire format
      `tokio_util`'s `LengthDelimitedCodec` (`framing::canonical`) produces directly on the
      substream -- `EncodeCanonicalFrame`'s output is not a payload that then needs an outer
      wrapper of its own; it already IS the complete on-the-wire message.

    Since negotiation frames and canonical frames are not self-distinguishing from each other in
    isolation (a canonical frame's first byte is not reliably a valid negotiation length, and
    vice versa), and both kinds share this one substream sequentially (negotiate once, then
    transition to RPC), `streamTransport.ReceiveFrame` needs to be told which kind to expect.
    This is done via an explicit, exported `rpc.BeginCanonicalFraming(Transport)` call: before
    it's called, `ReceiveFrame` parses negotiation frames (2-byte header); after it's called,
    `ReceiveFrame` parses canonical frames (4-byte header) instead. `SendFrame` needs no such
    switch, since it never adds framing of its own either way. `GetChainMetadata`
    (`chainmetadata.go`) calls `BeginCanonicalFraming` internally, immediately after
    `NegotiateProtocol` succeeds and before `PerformSessionHandshake` runs, so
    `p2p.ProbeChainMetadata`'s outbound/client call site needs no changes of its own for this.
    A Transport-over-a-shared-substream RESPONDER that drives `NegotiateProtocolInbound` and the
    RPC session handshake directly (rather than through `GetChainMetadata`) must call
    `BeginCanonicalFraming` itself at the equivalent point in its own sequence (see
    `p2p/yamux_rpc_integration_test.go`'s `serveGetChainMetadataOverStream` for exactly this).
    `BeginCanonicalFraming` is a documented no-op for any `Transport` implementation that doesn't
    need this distinction (e.g. this package's own tests operating directly on a `*p2p.Session`,
    where every message is already its own discrete Noise transport frame).

  #### Correction (same day, 2026-08-17): an earlier version of this fix double-wrapped every message

  The first version of `streamTransport` landed in this same pass wrapped BOTH negotiation
  frames AND canonical frames in an *additional*, generic u32-BE length prefix on top of the
  already-self-delimiting payload -- i.e. it treated `streamTransport` the way the Part A/B
  addendum's original (pre-Yamux) canonical framing worked, applying one uniform wrapper to
  everything crossing it. **This was wrong** and would have broken wire compatibility with real
  nodes: real Tari's `negotiation.rs` never wraps a negotiation frame in anything, and canonical
  framing (`tokio_util`'s `LengthDelimitedCodec`) already applies exactly one u32-BE length
  prefix per RPC message directly on the substream -- adding a second one on top, as the first
  version of this fix did, would have produced a stream a real node's own canonical/negotiation
  parsers do not expect (double length-prefixing, not single). This was caught and corrected
  before any live-node re-verification was attempted, based on a direct re-fetch/re-read of
  `comms/core/src/protocol/negotiation.rs`'s `write_frame_flush`/`read_frame`, which confirmed
  negotiation frames are written/read directly on the raw socket with no wrapper of any kind.
  The corrected design (no extra framing anywhere, explicit negotiation/canonical mode switch via
  `BeginCanonicalFraming`) is what's described above and is what actually shipped in this fix;
  the double-wrapping version never reached a commit describing itself as final/verified.
- **`p2p/chainmetadata_probe.go`** (`ProbeChainMetadata`, updated): after
  `InitiatorHandshake` succeeds, wraps the resulting `*Session` with `sessionReadWriteCloser`,
  establishes a `yamux.Client` session over that adapter, opens one substream
  (`yamuxSession.Open()`), wraps that substream with `rpc.NewStreamTransport`, and runs
  negotiation + the RPC session handshake + `get_chain_metadata` all on that one substream, in
  that order -- matching real Tari's own "negotiate then immediately transition to RPC on the
  same already-open substream" behaviour for a single-call client like this one (no need for
  multiple substreams here).
- `p2p/rpc/negotiation.go`, `p2p/rpc/handshake.go`, `p2p/rpc/canonicalframe.go`, and the
  `Transport` interface's method signatures themselves (`p2p/rpc/transport.go`) are
  **unchanged**. `p2p/rpc/chainmetadata.go` has exactly one small addition: a
  `BeginCanonicalFraming(session)` call inserted between the existing `NegotiateProtocol` and
  `PerformSessionHandshake` calls (see the `streamTransport` framing-decision bullet above for
  why) -- `GetChainMetadata`'s signature, and every other line of its own request/response
  encode/decode logic, are otherwise unchanged. This was, and remains, intended purely as "wire
  the existing, correct frame-encoding logic onto the correct underlying stream (plus the one
  minimal phase-transition signal that layering requires)" -- not a rewrite of any of these
  files' own payload encode/decode logic.

### Testing added for this fix

- **`p2p/rpc/streamtransport_test.go`** (new, package `rpc`, internal test since it needs
  unexported helpers like `encodeNegotiationFrame`/`decodeNegotiationFrame` for round-trip
  assertions): unit tests for `streamTransport` in isolation, over a real `net.Pipe()` (no Yamux,
  no Noise involved -- just the raw framing logic). Covers: `SendFrame` writes payload to the
  wire completely unmodified (byte-for-byte, no extra length prefix of any kind); `ReceiveFrame`
  correctly parses a negotiation frame written raw to the pipe (default/pre-
  `BeginCanonicalFraming` mode); `ReceiveFrame` correctly parses a canonical frame written raw to
  the pipe after `BeginCanonicalFraming` is called; `BeginCanonicalFraming` is a safe no-op for a
  `Transport` implementation that doesn't implement the internal switch; and a full negotiation-
  then-canonical round trip sharing one `net.Pipe()` sequentially, with `BeginCanonicalFraming`
  called on both ends in between, matching exactly the client/responder sequencing
  `GetChainMetadata`/`serveGetChainMetadataOverStream` use.
- **`p2p/yamuxadapter_test.go`** (new, package `p2p`, internal test since it needs the
  unexported `sessionReadWriteCloser`/`newSessionReadWriteCloser`): unit tests for the adapter in
  isolation, over a real Noise-handshaked `net.Pipe()` `*Session` pair (no Yamux involved) --
  `Write` round-trips a payload as a single `SendFrame` call; `Read` with a buffer exactly the
  size of one frame drains it in one call; `Read` with a buffer smaller than one frame requires
  multiple calls and correctly preserves/drains the leftover bytes across them; `Read` correctly
  moves on to a second frame after draining the first; `Close` closes the underlying `Session`.
- **`p2p/yamux_rpc_integration_test.go`** (new, package `p2p`,
  `TestGetChainMetadataOverRealYamuxSubstream`): the end-to-end test that actually would have
  caught this bug. Unlike `p2p/rpc/rpc_test.go`'s existing in-process tests (client and fake
  responder talking this package's protocol directly over the raw Noise session -- the exact
  layering bug this fix corrects, which is precisely why those tests did not catch it), this test
  runs a REAL `github.com/hashicorp/yamux` `Client`/`Server` session on top of a
  `net.Pipe()`-backed Noise `Session` pair, opens/accepts one real Yamux substream on each side,
  and only then runs protocol negotiation + the RPC session handshake + `get_chain_metadata` over
  that substream via `rpc.NewStreamTransport` -- i.e. it exercises the exact same
  Noise-Session -> `sessionReadWriteCloser` -> `yamux.Client`/`Open` -> `rpc.NewStreamTransport`
  -> `rpc.GetChainMetadata` call chain that `p2p.ProbeChainMetadata` now uses against a real node.
  Its fake responder helper, `serveGetChainMetadataOverStream`, calls `rpc.BeginCanonicalFraming`
  itself (mirroring what `GetChainMetadata` does internally on the client side), since it drives
  `NegotiateProtocolInbound`/`PerformSessionHandshakeResponder` directly rather than through
  `GetChainMetadata`.

  **This Yamux integration is Go-only, internally consistent (proven by this test's real,
  successful Yamux client+fake-responder round trip), and is explicitly NOT independently
  verified against real Tari Rust `yamux` wire behaviour** -- both ends of this test are this
  package's own Go code, not a real Tari Rust node. `github.com/hashicorp/yamux` is a widely used,
  separately-maintained implementation of the (roughly, and per its own `spec.md`) same Yamux
  protocol real Tari's Rust `yamux` crate implements, but "both implementations claim to speak
  the same spec" is not the same guarantee as "verified byte-compatible against each other over
  the wire." **Live-node re-verification of this fix is required before it can be considered
  final** -- that determination belongs to the dispatching agent, after re-testing against the
  same real Tari mainnet nodes that originally surfaced this bug, not to this pass.
