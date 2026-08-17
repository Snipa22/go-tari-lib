package p2p

import (
	"encoding/binary"
	"fmt"
	"time"

	"github.com/flynn/noise"
	googleproto "google.golang.org/protobuf/proto"

	identitypb "github.com/Snipa22/go-tari-lib/p2p/proto"
)

// identityProtocolMajorVersion is the single version byte sent in every identity protocol frame
// (source: tari/comms/core/src/protocol/network_info.rs, `NodeNetworkInfo.major_version`,
// `#[derive(Default)]` -> 0; and tari/comms/core/src/protocol/identity.rs, which writes this as
// `version_bytes = [version]` -- a single u8, NOT multiple version bytes).
const identityProtocolMajorVersion byte = 0

// maxIdentityProtocolMsgSize is `MAX_IDENTITY_PROTOCOL_MSG_SIZE` (source:
// tari/comms/core/src/protocol/identity.rs): a received (or sent) message declaring a length
// greater than this is a protocol violation / hostile peer and must be rejected.
const maxIdentityProtocolMsgSize = 1024

// outgoingUserAgent identifies this client in its outgoing PeerIdentityMsg.
const outgoingUserAgent = "go-tari-lib-p2p-probe/0.1"

// identityExchangeTimeout is the 10-second read timeout Tari applies while waiting for the
// peer's identity message (source: tari/comms/core/src/protocol/identity.rs,
// `identity_exchange`: `time::timeout(Duration::from_secs(10), read_protocol_frame(...))`).
const identityExchangeTimeout = 10 * time.Second

// IdentitySignature mirrors the wire `IdentitySignature` protobuf message (P2P_SPEC.md
// section 6 / p2p/proto/identity.proto) as plain Go types, so callers of this package don't need
// to depend on the generated protobuf types directly.
type IdentitySignature struct {
	Version     uint32
	Signature   []byte
	PublicNonce []byte
	UpdatedAt   int64
}

// PeerInfo is the result of a successful P2P probe (P2P_SPEC.md section 7).
type PeerInfo struct {
	Reachable bool

	// RemoteStaticPubKey is the peer's 32-byte canonical Ristretto255 public key, recovered from
	// the Noise_XX handshake.
	RemoteStaticPubKey []byte

	Addresses          [][]byte
	Features           uint32
	SupportedProtocols [][]byte
	UserAgent          string
	IdentitySignature  *IdentitySignature // nil if the peer didn't send one

	Latency time.Duration
}

// ourPeerIdentityMsgBytes builds and marshals this client's outgoing PeerIdentityMsg
// (P2P_SPEC.md section 6): empty addresses, features=0, empty supported_protocols,
// user_agent="go-tari-lib-p2p-probe/0.1", and a real IdentitySignature signed with
// staticKeypair (our own long-term Ristretto255 identity keypair -- the same one used for the
// Noise_XX handshake; see identity_signature.go for the signing algorithm).
//
// An earlier version of this function sent no IdentitySignature at all. Real Tari nodes validate
// every inbound PeerIdentityMsg (tari/comms/core/src/connection_manager/common.rs,
// `validate_peer_identity_message`) and reject one with no signature
// (`PeerManagerError::MissingIdentitySignature`), aborting the connection immediately after
// identity exchange -- before any Yamux traffic. That was a live-network-confirmed bug, not a
// deliberate simplification; see p2p/VERIFICATION.md's "Part D addendum" for the full writeup.
func ourPeerIdentityMsgBytes(staticKeypair noise.DHKey) ([]byte, error) {
	sig, err := buildOurIdentitySignature(staticKeypair)
	if err != nil {
		return nil, fmt.Errorf("p2p: building our own identity signature: %w", err)
	}

	msg := &identitypb.PeerIdentityMsg{
		Addresses:          nil,
		Features:           0,
		SupportedProtocols: nil,
		UserAgent:          outgoingUserAgent,
		IdentitySignature:  sig,
	}
	b, err := googleproto.Marshal(msg)
	if err != nil {
		return nil, fmt.Errorf("p2p: marshalling outgoing PeerIdentityMsg: %w", err)
	}
	return b, nil
}

// encodeIdentityProtocolFrame builds the identity protocol frame layout (P2P_SPEC.md section 5c
// / source: tari/comms/core/src/protocol/identity.rs, `write_protocol_frame`):
//
//	[1 byte version][2 bytes LE(u16) message length][protobuf PeerIdentityMsg bytes]
//
// This whole byte sequence is meant to be sent as the plaintext of exactly ONE Noise transport
// message (i.e. one Session.SendFrame call), not written as several separate transport frames.
func encodeIdentityProtocolFrame(msgBytes []byte) ([]byte, error) {
	if len(msgBytes) > maxIdentityProtocolMsgSize {
		return nil, fmt.Errorf("p2p: identity message of %d bytes exceeds MAX_IDENTITY_PROTOCOL_MSG_SIZE (%d)", len(msgBytes), maxIdentityProtocolMsgSize)
	}
	frame := make([]byte, 0, 1+2+len(msgBytes))
	frame = append(frame, identityProtocolMajorVersion)
	var lenBuf [2]byte
	binary.LittleEndian.PutUint16(lenBuf[:], uint16(len(msgBytes)))
	frame = append(frame, lenBuf[:]...)
	frame = append(frame, msgBytes...)
	return frame, nil
}

// decodeIdentityProtocolFrame parses the identity protocol frame layout described above and
// protobuf-decodes the inner PeerIdentityMsg, returning it as a *PeerInfo (with Reachable and
// Latency left at their zero values -- Probe fills those in). Fully surfaces whatever the peer
// sent (addresses, features, supported_protocols, user_agent, identity_signature), per
// P2P_SPEC.md section 6.
func decodeIdentityProtocolFrame(frame []byte) (*PeerInfo, error) {
	if len(frame) < 3 {
		return nil, fmt.Errorf("p2p: identity protocol frame too short (%d bytes, need at least 3)", len(frame))
	}

	version := frame[0]
	if version > identityProtocolMajorVersion {
		return nil, fmt.Errorf("p2p: unsupported peer identity protocol major version %d (max supported %d)", version, identityProtocolMajorVersion)
	}

	length := binary.LittleEndian.Uint16(frame[1:3])
	if length > maxIdentityProtocolMsgSize {
		return nil, fmt.Errorf("p2p: peer identity message declares length %d, exceeds MAX_IDENTITY_PROTOCOL_MSG_SIZE (%d)", length, maxIdentityProtocolMsgSize)
	}
	if int(length) > len(frame)-3 {
		return nil, fmt.Errorf("p2p: peer identity message declares length %d but only %d bytes were sent", length, len(frame)-3)
	}

	msg := &identitypb.PeerIdentityMsg{}
	if err := googleproto.Unmarshal(frame[3:3+int(length)], msg); err != nil {
		return nil, fmt.Errorf("p2p: decoding peer PeerIdentityMsg: %w", err)
	}

	info := &PeerInfo{
		Addresses:          msg.GetAddresses(),
		Features:           msg.GetFeatures(),
		SupportedProtocols: msg.GetSupportedProtocols(),
		UserAgent:          msg.GetUserAgent(),
	}
	if sig := msg.GetIdentitySignature(); sig != nil {
		info.IdentitySignature = &IdentitySignature{
			Version:     sig.GetVersion(),
			Signature:   sig.GetSignature(),
			PublicNonce: sig.GetPublicNonce(),
			UpdatedAt:   sig.GetUpdatedAt(),
		}
	}
	return info, nil
}
