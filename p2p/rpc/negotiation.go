package rpc

import (
	"errors"
	"fmt"
)

// Protocol negotiation frame flags (source: tari/comms/core/src/protocol/negotiation.rs,
// bitflags on the frame's second byte).
const (
	negotiationFlagNone         byte = 0x00
	negotiationFlagOptimistic   byte = 0x01 // not used by this client -- we do non-optimistic negotiation
	negotiationFlagTerminate    byte = 0x02
	negotiationFlagNotSupported byte = 0x04
)

// maxProtocolIDLen is the maximum length of a protocol id in a negotiation frame -- the frame's
// length byte is a single u8, so a protocol id can be at most 255 bytes (source:
// tari/comms/core/src/protocol/negotiation.rs).
const maxProtocolIDLen = 255

// ErrProtocolNotSupported is returned by NegotiateProtocol when the peer signals (via the
// NOT_SUPPORTED flag, or a TERMINATE, or an unexpected echoed protocol id) that it does not
// support the protocol we asked to negotiate. This is an EXPECTED, non-fatal outcome (e.g. a
// peer not running blksync), not a bug -- callers should check for it with errors.Is.
var ErrProtocolNotSupported = errors.New("rpc: peer does not support the requested protocol")

// ErrProtocolTerminated is returned by NegotiateProtocol when the peer terminates negotiation
// (the TERMINATE flag). Also matches errors.Is(err, ErrProtocolNotSupported), since from this
// client's point of view both outcomes mean "can't use this protocol with this peer" -- but the
// more specific sentinel is available for callers that want to distinguish the two.
var ErrProtocolTerminated = fmt.Errorf("rpc: peer terminated protocol negotiation: %w", ErrProtocolNotSupported)

// encodeNegotiationFrame builds the protocol negotiation frame layout (source:
// tari/comms/core/src/protocol/negotiation.rs doc comment + code):
//
//	| len (1 byte, u8 BE) | flags (1 byte) | protocol id (variable, max 255 bytes) |
//
// This whole byte sequence is sent AS THE PLAINTEXT ARGUMENT to (Transport).SendFrame
// directly -- NO canonical (u32 BE length-prefixed) wrapper around negotiation frames (see
// p2p/RPC_TOR_SPEC.md section A0 for why, byte-exact traced against real Tari source).
func encodeNegotiationFrame(flags byte, protocolID []byte) ([]byte, error) {
	if len(protocolID) > maxProtocolIDLen {
		return nil, fmt.Errorf("rpc: protocol id of %d bytes exceeds the maximum of %d", len(protocolID), maxProtocolIDLen)
	}
	frame := make([]byte, 0, 2+len(protocolID))
	frame = append(frame, byte(len(protocolID)))
	frame = append(frame, flags)
	frame = append(frame, protocolID...)
	return frame, nil
}

// decodeNegotiationFrame parses the protocol negotiation frame layout described above, returning
// the flags byte and the protocol id bytes it declares.
func decodeNegotiationFrame(frame []byte) (flags byte, protocolID []byte, err error) {
	if len(frame) < 2 {
		return 0, nil, fmt.Errorf("rpc: negotiation frame too short (%d bytes, need at least 2)", len(frame))
	}
	length := frame[0]
	flags = frame[1]
	rest := frame[2:]
	if int(length) != len(rest) {
		return 0, nil, fmt.Errorf("rpc: negotiation frame declares protocol id length %d but %d bytes follow the header", length, len(rest))
	}
	return flags, rest, nil
}

// NegotiateProtocol performs the CLIENT (outbound/initiator) side of protocol negotiation over
// session (source: tari/comms/core/src/protocol/negotiation.rs, `negotiate_protocol_outbound`,
// non-optimistic path):
//
//  1. Write a negotiation frame with flags=NONE and the given protocolID.
//  2. Read a negotiation frame back.
//     - TERMINATE flag set -> ErrProtocolTerminated (also matches ErrProtocolNotSupported via
//     errors.Is).
//     - NOT_SUPPORTED flag set -> ErrProtocolNotSupported.
//     - Echoed protocol id byte-exact matches protocolID -> success, return nil.
//     - Otherwise -> ErrProtocolNotSupported (protocol mismatch; treated the same as
//     "not supported" from this client's point of view, since this client only ever offers a
//     single candidate protocol id per call).
//
// The real Rust client loops over a list of candidate protocols here, since it supports
// multi-protocol negotiation; this client only ever negotiates ONE protocol id per call, so a
// single round is sufficient. Structured as a single function (rather than a loop over one
// element) so a future multi-protocol client could be added without a rewrite of the frame
// encode/decode helpers above.
func NegotiateProtocol(session Transport, protocolID []byte) error {
	outFrame, err := encodeNegotiationFrame(negotiationFlagNone, protocolID)
	if err != nil {
		return err
	}
	if err := session.SendFrame(outFrame); err != nil {
		return fmt.Errorf("rpc: sending protocol negotiation frame: %w", err)
	}

	inFrame, err := session.ReceiveFrame()
	if err != nil {
		return fmt.Errorf("rpc: receiving protocol negotiation reply: %w", err)
	}
	flags, echoedProtocol, err := decodeNegotiationFrame(inFrame)
	if err != nil {
		return fmt.Errorf("rpc: parsing protocol negotiation reply: %w", err)
	}

	if flags&negotiationFlagTerminate != 0 {
		return ErrProtocolTerminated
	}
	if flags&negotiationFlagNotSupported != 0 {
		return fmt.Errorf("rpc: peer does not support protocol %q: %w", protocolID, ErrProtocolNotSupported)
	}
	if !bytesEqual(echoedProtocol, protocolID) {
		return fmt.Errorf("rpc: peer echoed unexpected protocol id %q (wanted %q): %w", echoedProtocol, protocolID, ErrProtocolNotSupported)
	}
	return nil
}

// NegotiateProtocolInbound performs the RESPONDER (inbound) side of protocol negotiation over
// session (source: tari/comms/core/src/protocol/negotiation.rs, `negotiate_protocol_inbound`
// semantics): read a negotiation frame, and if the requested protocol id is byte-exact present
// in supportedProtocols, reply with flags=NONE echoing that protocol id; otherwise reply with
// flags=NOT_SUPPORTED and an empty protocol id.
//
// This is provided primarily to support this package's own in-process tests (a real responder
// role is out of scope for this client -- see p2p/RPC_TOR_SPEC.md section A4), but is exported
// since it's a clean, reusable, non-test-specific building block.
func NegotiateProtocolInbound(session Transport, supportedProtocols [][]byte) (negotiatedProtocol []byte, err error) {
	inFrame, err := session.ReceiveFrame()
	if err != nil {
		return nil, fmt.Errorf("rpc: receiving protocol negotiation frame: %w", err)
	}
	_, requested, err := decodeNegotiationFrame(inFrame)
	if err != nil {
		return nil, fmt.Errorf("rpc: parsing protocol negotiation frame: %w", err)
	}

	var supported bool
	for _, p := range supportedProtocols {
		if bytesEqual(p, requested) {
			supported = true
			break
		}
	}

	if !supported {
		outFrame, err := encodeNegotiationFrame(negotiationFlagNotSupported, nil)
		if err != nil {
			return nil, err
		}
		if err := session.SendFrame(outFrame); err != nil {
			return nil, fmt.Errorf("rpc: sending NOT_SUPPORTED negotiation reply: %w", err)
		}
		return nil, fmt.Errorf("rpc: peer requested unsupported protocol %q: %w", requested, ErrProtocolNotSupported)
	}

	outFrame, err := encodeNegotiationFrame(negotiationFlagNone, requested)
	if err != nil {
		return nil, err
	}
	if err := session.SendFrame(outFrame); err != nil {
		return nil, fmt.Errorf("rpc: sending negotiation success reply: %w", err)
	}
	return requested, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
