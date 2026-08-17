package p2p

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/flynn/noise"
)

// networkWireByte is the single byte the dialing/outbound side writes immediately after TCP
// connect, BEFORE any Noise bytes (source: tari/comms/core/src/protocol/network_info.rs,
// `NodeNetworkInfo.network_wire_byte`, `#[derive(Default)]` -> `0x00`).
//
// The reserved value `0xa7` (`LIVENESS_WIRE_MODE`, source:
// tari/comms/core/src/connection_manager/wire_mode.rs) is documented here for context only --
// this package never implements or emits liveness-wire-mode; it always sends 0x00.
const networkWireByte byte = 0x00

// tariPrologue is the exact Noise prologue byte string Tari uses for every comms connection
// (source: tari/comms/core/src/noise/config.rs, `NoiseConfig::upgrade_socket`, local constant
// `TARI_PROLOGUE: &[u8] = b"com.tari.comms.noise.prologue"`). No null terminator, plain ASCII.
var tariPrologue = []byte("com.tari.comms.noise.prologue")

// newTariCipherSuite builds the flynn/noise CipherSuite matching Tari's Noise parameters
// (source: tari/comms/core/src/noise/config.rs, `NOISE_PARAMETERS = "Noise_XX_25519_ChaChaPoly_BLAKE2b"`):
// RistrettoDH (see ristretto_dh.go for the DHName "25519" naming quirk), ChaCha20-Poly1305, and
// BLAKE2b (BLAKE2b-512, used internally by Noise for handshake-hash/chaining-key mixing -- a
// different Blake2b usage from the domain-separated Blake2b-256 DH-output KDF in hashing.go;
// don't conflate the two).
func newTariCipherSuite() noise.CipherSuite {
	return noise.NewCipherSuite(RistrettoDH{}, noise.CipherChaChaPoly, noise.HashBLAKE2b)
}

// InitiatorHandshake writes the network wire byte, then performs the 3-message Noise_XX
// handshake as the initiator (source: tari/comms/core/src/noise/socket.rs,
// `Handshake::handshake_1_5rtt`, initiator branch):
//
//	-> e            (msg1)
//	<- e, ee, s, es (msg2; recovers the peer's static public key)
//	-> s, se        (msg3; handshake completes, cipher states are produced)
//
// Every message (including these handshake messages) is wrapped in a u16-BE length-prefixed
// frame on the wire -- see the doc comment on writeFrame in frame.go for why, based on
// inspecting the real `NoiseSocket` implementation in tari/comms/core/src/noise/socket.rs.
//
// conn must already be a connected net.Conn (dialing is the caller's responsibility, e.g. via
// Probe). staticKeypair is our own long-term Ristretto255 identity keypair.
func InitiatorHandshake(ctx context.Context, conn net.Conn, staticKeypair noise.DHKey) (*Session, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	if _, err := conn.Write([]byte{networkWireByte}); err != nil {
		return nil, fmt.Errorf("p2p: writing network wire byte: %w", err)
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   newTariCipherSuite(),
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		Prologue:      tariPrologue,
		StaticKeypair: staticKeypair,
	})
	if err != nil {
		return nil, fmt.Errorf("p2p: initializing initiator handshake state: %w", err)
	}

	// msg1: -> e
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("p2p: building handshake message 1 (-> e): %w", err)
	}
	if err := writeFrame(conn, msg1); err != nil {
		return nil, fmt.Errorf("p2p: sending handshake message 1: %w", err)
	}

	// <- e, ee, s, es
	msg2, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("p2p: receiving handshake message 2: %w", err)
	}
	if _, _, _, err := hs.ReadMessage(nil, msg2); err != nil {
		return nil, fmt.Errorf("p2p: processing handshake message 2 (<- e, ee, s, es): %w", err)
	}

	// -> s, se  (handshake completes here; cs1 is our send cipher, cs2 our receive cipher)
	msg3, cs1, cs2, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("p2p: building handshake message 3 (-> s, se): %w", err)
	}
	if cs1 == nil || cs2 == nil {
		return nil, fmt.Errorf("p2p: handshake message 3 did not complete the handshake (no cipher states returned)")
	}
	if err := writeFrame(conn, msg3); err != nil {
		return nil, fmt.Errorf("p2p: sending handshake message 3: %w", err)
	}

	peerStatic := hs.PeerStatic()
	if len(peerStatic) != 32 {
		return nil, fmt.Errorf("p2p: expected a 32-byte peer static public key, got %d bytes", len(peerStatic))
	}

	return &Session{
		conn:          conn,
		tx:            cs1,
		rx:            cs2,
		PeerStaticKey: append([]byte(nil), peerStatic...),
	}, nil
}

// ResponderHandshake is a minimal responder-side counterpart to InitiatorHandshake, provided
// only so the initiator implementation above can be exercised against something real in an
// in-process test (see p2p_test.go). It is intentionally NOT a full
// listener/connection-manager/address-book abstraction -- just enough of the responder side of
// `Handshake::handshake_1_5rtt` to complete a Noise_XX handshake.
//
// Per P2P_SPEC.md section 5a, only the dialing/outbound side writes the network wire byte; the
// responder is expected to read (and, for this minimal implementation, simply discard/validate)
// that single byte before starting the Noise handshake proper.
func ResponderHandshake(ctx context.Context, conn net.Conn, staticKeypair noise.DHKey) (*Session, error) {
	if err := checkContext(ctx); err != nil {
		return nil, err
	}

	wireByte := make([]byte, 1)
	if _, err := io.ReadFull(conn, wireByte); err != nil {
		return nil, fmt.Errorf("p2p: reading network wire byte: %w", err)
	}
	if wireByte[0] == liveWireMode {
		return nil, fmt.Errorf("p2p: peer requested liveness wire mode (0x%x), which this package does not implement", liveWireMode)
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   newTariCipherSuite(),
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		Prologue:      tariPrologue,
		StaticKeypair: staticKeypair,
	})
	if err != nil {
		return nil, fmt.Errorf("p2p: initializing responder handshake state: %w", err)
	}

	// -> e
	msg1, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("p2p: receiving handshake message 1: %w", err)
	}
	if _, _, _, err := hs.ReadMessage(nil, msg1); err != nil {
		return nil, fmt.Errorf("p2p: processing handshake message 1 (-> e): %w", err)
	}

	// <- e, ee, s, es
	msg2, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("p2p: building handshake message 2 (<- e, ee, s, es): %w", err)
	}
	if err := writeFrame(conn, msg2); err != nil {
		return nil, fmt.Errorf("p2p: sending handshake message 2: %w", err)
	}

	// -> s, se (handshake completes here; cs1 is the initiator's send cipher = our receive
	// cipher, cs2 is the initiator's receive cipher = our send cipher)
	msg3, err := readFrame(conn)
	if err != nil {
		return nil, fmt.Errorf("p2p: receiving handshake message 3: %w", err)
	}
	_, cs1, cs2, err := hs.ReadMessage(nil, msg3)
	if err != nil {
		return nil, fmt.Errorf("p2p: processing handshake message 3 (-> s, se): %w", err)
	}
	if cs1 == nil || cs2 == nil {
		return nil, fmt.Errorf("p2p: handshake message 3 did not complete the handshake (no cipher states returned)")
	}

	peerStatic := hs.PeerStatic()
	if len(peerStatic) != 32 {
		return nil, fmt.Errorf("p2p: expected a 32-byte peer static public key, got %d bytes", len(peerStatic))
	}

	return &Session{
		conn:          conn,
		tx:            cs2,
		rx:            cs1,
		PeerStaticKey: append([]byte(nil), peerStatic...),
	}, nil
}

// liveWireMode is `LIVENESS_WIRE_MODE` (source:
// tari/comms/core/src/connection_manager/wire_mode.rs), documented for context only -- see
// networkWireByte above. Not implemented, only checked for and rejected with a clear error.
const liveWireMode byte = 0xa7

func checkContext(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return fmt.Errorf("p2p: context done before starting handshake: %w", ctx.Err())
	default:
		return nil
	}
}
