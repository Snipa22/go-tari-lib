package rpc

import (
	"encoding/binary"
	"fmt"
	"io"
)

// negotiationFrameHeaderSize is the size, in bytes, of a protocol negotiation frame's own header
// (1-byte length + 1-byte flags) -- see negotiation.go's encodeNegotiationFrame/
// decodeNegotiationFrame. Real Tari's own negotiation.rs write_frame_flush/read_frame
// (comms/core/src/protocol/negotiation.rs) write/read exactly this many header bytes directly on
// the raw substream (then exactly `length` more body bytes), with NO additional outer
// length-prefix wrapper around the whole message -- a negotiation frame is entirely
// self-delimiting on its own.
const negotiationFrameHeaderSize = 2

// canonicalFrameLenPrefixSizeOnStream is the size, in bytes, of a canonical frame's own u32-BE
// length prefix, as already produced by EncodeCanonicalFrame/consumed by DecodeCanonicalFrame
// (canonicalframe.go). Named separately from canonicalFrameLenPrefixSize (same value) purely so
// this file's own doc comments can refer to "the length prefix as it appears on the raw stream"
// without implying a dependency on canonicalframe.go's internal constant.
const canonicalFrameLenPrefixSizeOnStream = 4

// streamTransport implements Transport (SendFrame/ReceiveFrame -- exactly ONE complete message
// per call, matching negotiation.go's and canonicalframe.go's existing one-call-per-message
// contract) directly on top of a raw io.ReadWriteCloser byte stream, such as a yamux substream
// (net.Conn) opened over an already-Noise-handshaked p2p.Session.
//
// Framing decision (see p2p/VERIFICATION.md's dated section for the full writeup, including the
// correction recorded here): streamTransport adds ZERO extra framing of its own. Both message
// kinds that flow over it are already fully self-delimiting on their own:
//
//   - Protocol negotiation frames (negotiation.go's encodeNegotiationFrame/
//     decodeNegotiationFrame): [1-byte length][1-byte flags][protocol id, `length` bytes]. Real
//     Tari's negotiation.rs writes/reads exactly this, with nothing extra around it
//     (write_frame_flush/read_frame operate directly on the raw socket).
//   - Canonical RPC frames (canonicalframe.go's EncodeCanonicalFrame/DecodeCanonicalFrame):
//     [4-byte u32-BE length][payload, `length` bytes]. This is ALREADY the exact wire format
//     tokio_util's LengthDelimitedCodec (`framing::canonical`) produces directly on the
//     substream -- EncodeCanonicalFrame's output is not a payload that then needs its own outer
//     wrapper; it already IS the complete on-the-wire message.
//
// An earlier version of this file wrapped BOTH kinds of message in an additional, generic
// u32-BE length prefix on top of the already-self-delimiting payload -- this was WRONG (double
// framing that no real Tari node produces or expects) and broke wire compatibility with real
// nodes. streamTransport's SendFrame therefore writes whatever payload it's given straight to
// the stream, completely unmodified; ReceiveFrame's only job is to know how many bytes to pull
// off the raw stream to reconstruct exactly one such self-delimiting message -- which differs
// between the two message kinds (2-byte header vs 4-byte header), hence the canonical/negotiation
// mode switch below.
//
// Negotiation and canonical-framed RPC traffic share this one substream sequentially (negotiate
// once, then transition to RPC), and negotiation frames and canonical frames are NOT
// self-distinguishing from each other in isolation (a canonical frame's first byte is not
// reliably a valid negotiation length, and vice versa) -- so streamTransport must be explicitly
// told when negotiation has finished and canonical framing begins, via BeginCanonicalFraming.
// Before that call, ReceiveFrame parses negotiation-framed messages; after it, ReceiveFrame
// parses canonical-framed messages. SendFrame needs no such mode switch, since it never adds
// framing of its own regardless of message kind -- only ReceiveFrame's parsing differs.
//
// stream is typically a yamux substream (net.Conn), but only io.ReadWriteCloser is required.
type streamTransport struct {
	stream io.ReadWriteCloser

	// canonical is false (negotiation-frame parsing) until BeginCanonicalFraming switches it to
	// true (canonical-frame parsing) -- see BeginCanonicalFraming's doc comment for who is
	// responsible for calling it and when.
	canonical bool
}

// NewStreamTransport wraps stream (e.g. a yamux substream) as a Transport that adds NO extra
// framing of its own -- see the package-level doc comment on streamTransport for the framing
// decision this makes. Callers (e.g. p2p.ProbeChainMetadata) that have a raw byte-stream
// substream (such as a yamux substream opened over an already-Noise-handshaked connection) and
// need a Transport to pass to NegotiateProtocol/PerformSessionHandshake/GetChainMetadata should
// wrap it with this.
//
// The returned Transport starts in negotiation-framing mode; whatever calls NegotiateProtocol/
// NegotiateProtocolInbound to completion is responsible for calling BeginCanonicalFraming
// afterwards, before performing the RPC session handshake (GetChainMetadata does this
// automatically for the outbound/client path; see its doc comment).
func NewStreamTransport(stream io.ReadWriteCloser) Transport {
	return &streamTransport{stream: stream}
}

// canonicalFramingSwitch is the internal interface BeginCanonicalFraming uses to signal the
// negotiation-to-canonical framing transition to a Transport implementation that needs it (in
// practice, only *streamTransport). Transport implementations that don't need this distinction
// (e.g. this package's own tests operating directly on a *p2p.Session, where every message is
// already its own discrete Noise transport frame with no shared-byte-stream framing ambiguity to
// resolve) simply don't implement it, making BeginCanonicalFraming a safe no-op for them.
type canonicalFramingSwitch interface {
	beginCanonicalFraming()
}

// BeginCanonicalFraming signals a Transport that protocol negotiation has completed and all
// subsequent SendFrame/ReceiveFrame traffic on it should be parsed as canonical (u32-BE
// length-prefixed) frames rather than protocol negotiation frames.
//
// This is necessary because a streamTransport-wrapped raw byte-stream substream carries both
// message kinds sequentially with no framing-of-the-framing to tell them apart automatically;
// callers that drive NegotiateProtocol/NegotiateProtocolInbound directly (rather than through
// GetChainMetadata, which already does this internally for the outbound path -- see its doc
// comment) and then go on to perform the RPC session handshake and/or RPC calls on the SAME
// Transport value must call BeginCanonicalFraming exactly once, right after negotiation succeeds
// and before the first canonical-framed SendFrame/ReceiveFrame call.
//
// A no-op for any Transport implementation that doesn't need this distinction (see
// canonicalFramingSwitch).
func BeginCanonicalFraming(t Transport) {
	if switcher, ok := t.(canonicalFramingSwitch); ok {
		switcher.beginCanonicalFraming()
	}
}

func (t *streamTransport) beginCanonicalFraming() {
	t.canonical = true
}

// SendFrame writes payload to the stream completely as-is, with NO added framing of any kind.
// payload is expected to already be one complete, self-delimiting message -- either a
// negotiation frame (encodeNegotiationFrame's output) or a canonical frame
// (EncodeCanonicalFrame's output) -- so a single SendFrame call produces exactly that payload's
// bytes on the wire, matching real Tari's own behaviour exactly for both message kinds (see the
// package-level doc comment above).
func (t *streamTransport) SendFrame(payload []byte) error {
	if _, err := t.stream.Write(payload); err != nil {
		return fmt.Errorf("rpc: stream transport: writing frame: %w", err)
	}
	return nil
}

// ReceiveFrame reads a single complete, self-delimiting message from the stream and returns it
// verbatim (header bytes included, matching what decodeNegotiationFrame/DecodeCanonicalFrame
// expect to parse), using negotiation-frame parsing or canonical-frame parsing depending on
// whether BeginCanonicalFraming has been called yet -- see the package-level doc comment above.
func (t *streamTransport) ReceiveFrame() ([]byte, error) {
	if t.canonical {
		return t.receiveCanonicalFrame()
	}
	return t.receiveNegotiationFrame()
}

// receiveNegotiationFrame reads exactly one protocol negotiation frame off the stream: a 2-byte
// header (1-byte length + 1-byte flags), then exactly `length` more body bytes -- mirroring real
// Tari's negotiation.rs `read_frame` byte-for-byte, with no outer wrapper to strip. Looping via
// io.ReadFull is necessary since a single net.Conn Read call is not guaranteed to return the
// whole header or the whole body at once.
func (t *streamTransport) receiveNegotiationFrame() ([]byte, error) {
	header := make([]byte, negotiationFrameHeaderSize)
	if _, err := io.ReadFull(t.stream, header); err != nil {
		return nil, fmt.Errorf("rpc: stream transport: reading negotiation frame header: %w", err)
	}
	length := header[0]
	if length == 0 {
		return header, nil
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(t.stream, body); err != nil {
		return nil, fmt.Errorf("rpc: stream transport: reading negotiation frame body (%d bytes): %w", length, err)
	}
	return append(header, body...), nil
}

// receiveCanonicalFrame reads exactly one canonical frame off the stream: a 4-byte u32-BE length
// prefix, then exactly that many more payload bytes -- mirroring the exact wire format
// EncodeCanonicalFrame already produces/DecodeCanonicalFrame already expects, with no additional
// outer wrapper. Looping via io.ReadFull is necessary since a single net.Conn Read call is not
// guaranteed to return the whole length prefix or the whole payload at once.
func (t *streamTransport) receiveCanonicalFrame() ([]byte, error) {
	lenPrefix := make([]byte, canonicalFrameLenPrefixSizeOnStream)
	if _, err := io.ReadFull(t.stream, lenPrefix); err != nil {
		return nil, fmt.Errorf("rpc: stream transport: reading canonical frame length prefix: %w", err)
	}
	n := binary.BigEndian.Uint32(lenPrefix)
	if n == 0 {
		return lenPrefix, nil
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(t.stream, payload); err != nil {
		return nil, fmt.Errorf("rpc: stream transport: reading canonical frame payload (%d bytes): %w", n, err)
	}
	return append(lenPrefix, payload...), nil
}
