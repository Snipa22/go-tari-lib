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

// FeaturesCommunicationNode is the wire value of `PeerFeatures::COMMUNICATION_NODE` (source:
// tari/comms/core/src/peer_manager/peer_features.rs):
//
//	const MESSAGE_PROPAGATION = 0b0000_0001;
//	const DHT_STORE_FORWARD   = 0b0000_0010;
//	COMMUNICATION_NODE = MESSAGE_PROPAGATION | DHT_STORE_FORWARD; // = 3
//
// A real Tari node's DHT connectivity pool silently no-ops and never pools/gossips a peer whose
// advertised features `.is_client()` (comms/dht/src/connectivity/mod.rs,
// handle_new_peer_connected) -- i.e. a peer advertising `COMMUNICATION_CLIENT` (0, this
// package's unchanged default -- see IdentityOptions) will never be treated as a routable node
// by a real peer, only as a client. Pass this value as IdentityOptions.Features to
// ExchangeIdentityWithOptions to advertise COMMUNICATION_NODE instead.
const FeaturesCommunicationNode uint32 = 0b0000_0001 | 0b0000_0010

// IdentityOptions configures the OUTGOING PeerIdentityMsg an ExchangeIdentityWithOptions call
// sends. The zero value (Features=0 i.e. COMMUNICATION_CLIENT, Addresses=nil) matches
// ExchangeIdentity's existing, unchanged behavior exactly -- this type only exists so callers
// that need something other than that default (e.g. a responder wanting to advertise
// COMMUNICATION_NODE, see FeaturesCommunicationNode) can opt in explicitly, without altering
// ExchangeIdentity's behavior for every existing caller (P2P/RPC probes).
type IdentityOptions struct {
	// Features is the peer_features bitmask advertised in our outgoing PeerIdentityMsg.Features
	// (source: tari/comms/core/src/peer_manager/peer_features.rs). See FeaturesCommunicationNode.
	// This exact value is also chained into the outgoing IdentitySignature's challenge (see
	// identity_signature.go's buildOurIdentitySignature) -- a real Tari peer recomputes that
	// challenge from whatever Features it actually receives, so this MUST be the true claimed
	// value, not a placeholder.
	Features uint32
	// Addresses is advertised in our outgoing PeerIdentityMsg.Addresses, and is ALSO chained
	// (in this exact order) into the outgoing IdentitySignature's challenge, for the same reason
	// as Features above. nil/empty is fine (and is ExchangeIdentity's existing, unchanged
	// behavior) -- a peer with no advertised reachable address is still valid, just not
	// independently dialable by others from this identity message alone.
	//
	// Each element MUST already be that address's raw BINARY rust-multiaddr wire encoding (see
	// multiaddr.go's EncodeMultiaddrString), NOT a UTF-8 multiaddr string -- confirmed from real
	// Tari source, see multiaddr.go's doc comment for the full chain of evidence.
	Addresses [][]byte
}

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
// (P2P_SPEC.md section 6): the given addresses/features, empty supported_protocols,
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
//
// A LATER version of this function hardcoded the IdentitySignature's challenge to always sign
// features=0/no addresses, even when features/addresses here were non-zero/non-empty (BRIEF2.md
// "THE BUG") -- a real Tari peer recomputes the challenge from the features/addresses it
// actually received in THIS message and rejects the connection (or worse, silently drops it) if
// the signature doesn't match. buildOurIdentitySignature now takes features/addresses directly
// so the signature always attests to exactly what this message claims.
func ourPeerIdentityMsgBytes(staticKeypair noise.DHKey, features uint32, addresses [][]byte) ([]byte, error) {
	sig, err := buildOurIdentitySignature(staticKeypair, features, addresses)
	if err != nil {
		return nil, fmt.Errorf("p2p: building our own identity signature: %w", err)
	}

	msg := &identitypb.PeerIdentityMsg{
		Addresses:          addresses,
		Features:           features,
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
