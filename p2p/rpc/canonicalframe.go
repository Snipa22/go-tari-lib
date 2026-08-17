// Package rpc implements a minimal RPC-over-P2P client on top of the `p2p` package's Session
// (Noise_XX transport), enough to negotiate the `t/blksync/1` protocol, perform the RPC session
// handshake, and issue a single `get_chain_metadata` request/response.
//
// See p2p/RPC_TOR_SPEC.md (as fetched/resolved from real Tari source at implementation time) and
// p2p/VERIFICATION.md for the byte-exact-verified-vs-Go-only-internally-consistent disclosure of
// every wire-format detail implemented here.
package rpc

import (
	"encoding/binary"
	"fmt"
)

// canonicalFrameLenPrefixSize is the size, in bytes, of the length prefix used by
// EncodeCanonicalFrame/DecodeCanonicalFrame below.
const canonicalFrameLenPrefixSize = 4

// EncodeCanonicalFrame prepends a 4-byte big-endian length prefix to payload, matching
// `tokio_util::codec::LengthDelimitedCodec`'s default `length_field_type`/`big_endian` settings
// (source: tari/comms/core/src/framing.rs, `framing::canonical`). This is the framing used for
// the RPC session handshake and RPC request/response messages (NOT protocol negotiation, which
// is sent as the raw plaintext of a Noise transport frame with no canonical wrapper -- see
// negotiation.go).
//
// The resulting byte sequence is meant to be passed directly as the plaintext argument to
// (*p2p.Session).SendFrame -- i.e. one canonical frame per one Noise transport message.
func EncodeCanonicalFrame(payload []byte) []byte {
	frame := make([]byte, canonicalFrameLenPrefixSize+len(payload))
	binary.BigEndian.PutUint32(frame[:canonicalFrameLenPrefixSize], uint32(len(payload)))
	copy(frame[canonicalFrameLenPrefixSize:], payload)
	return frame
}

// DecodeCanonicalFrame strips the 4-byte big-endian length prefix from frame (as produced by
// EncodeCanonicalFrame) and returns the payload, validating that the declared length matches the
// number of bytes actually present after the prefix.
//
// frame is expected to be the plaintext returned by (*p2p.Session).ReceiveFrame -- i.e. one
// canonical frame per one Noise transport message.
func DecodeCanonicalFrame(frame []byte) ([]byte, error) {
	if len(frame) < canonicalFrameLenPrefixSize {
		return nil, fmt.Errorf("rpc: canonical frame too short (%d bytes, need at least %d for the length prefix)", len(frame), canonicalFrameLenPrefixSize)
	}
	declaredLen := binary.BigEndian.Uint32(frame[:canonicalFrameLenPrefixSize])
	payload := frame[canonicalFrameLenPrefixSize:]
	if int(declaredLen) != len(payload) {
		return nil, fmt.Errorf("rpc: canonical frame declares payload length %d but %d bytes follow the length prefix", declaredLen, len(payload))
	}
	return payload, nil
}
