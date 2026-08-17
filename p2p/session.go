package p2p

import (
	"context"
	"fmt"
	"net"

	"github.com/flynn/noise"
)

// Session wraps a post-Noise_XX-handshake net.Conn together with the tx/rx CipherStates produced
// by the handshake and the peer's recovered static public key. It provides methods to send/
// receive length-prefixed encrypted transport frames (source:
// tari/comms/core/src/noise/socket.rs) and, built on top of those, the identity exchange
// protocol (source: tari/comms/core/src/protocol/identity.rs).
type Session struct {
	conn net.Conn
	tx   *noise.CipherState
	rx   *noise.CipherState

	// PeerStaticKey is the peer's 32-byte canonical Ristretto255 static public key, recovered
	// via HandshakeState.PeerStatic() once the handshake completed.
	PeerStaticKey []byte

	// LocalStaticKeypair is OUR OWN long-term Ristretto255 identity keypair -- the same
	// staticKeypair passed into InitiatorHandshake/ResponderHandshake, threaded through so
	// ExchangeIdentity can sign our own outgoing PeerIdentityMsg with it (see
	// identity_signature.go). This is deliberately a plain field, not a method, since both
	// handshake constructors already have the keypair in hand and there is nothing to compute
	// lazily.
	LocalStaticKeypair noise.DHKey
}

// Close closes the underlying connection.
func (s *Session) Close() error {
	return s.conn.Close()
}

// SendFrame encrypts plaintext as a single Noise transport message (one CipherState.Encrypt
// call, i.e. one Noise transport message per frame, NOT a raw stream cipher -- source:
// tari/comms/core/src/noise/socket.rs) and writes the resulting ciphertext to the connection
// wrapped in a u16-BE length-prefixed frame (see frame.go).
func (s *Session) SendFrame(plaintext []byte) error {
	ciphertext, err := s.tx.Encrypt(nil, nil, plaintext)
	if err != nil {
		return fmt.Errorf("p2p: encrypting transport frame: %w", err)
	}
	if err := writeFrame(s.conn, ciphertext); err != nil {
		return fmt.Errorf("p2p: sending transport frame: %w", err)
	}
	return nil
}

// ReceiveFrame reads a single u16-BE length-prefixed frame from the connection and decrypts it
// as one Noise transport message, returning the plaintext.
func (s *Session) ReceiveFrame() ([]byte, error) {
	ciphertext, err := readFrame(s.conn)
	if err != nil {
		return nil, fmt.Errorf("p2p: receiving transport frame: %w", err)
	}
	plaintext, err := s.rx.Decrypt(nil, nil, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("p2p: decrypting transport frame: %w", err)
	}
	return plaintext, nil
}

// ExchangeIdentity performs the Tari comms identity-exchange protocol on top of this Session
// (source: tari/comms/core/src/protocol/identity.rs, `identity_exchange`): both sides write
// their own PeerIdentityMsg immediately (half-RTT, not request/response), matching Tari's own
// doc comment:
//
//	[initiator]   (simultaneous)   [responder]
//	  |  ---------[identity]--------> |
//	  |  <---------[identity]-------- |
//
// The send and receive halves are run concurrently (rather than write-then-read sequentially)
// specifically because they must be genuinely simultaneous, not just issued back-to-back: over a
// real TCP connection a sequential write-then-read would work fine (the OS socket send buffer
// absorbs the write even before the peer reads), but a fully synchronous, unbuffered transport
// (such as net.Pipe, used in this package's own tests) requires an active reader on the peer's
// side for a write to complete at all -- if both sides insist on finishing their own write
// before starting to read, and neither has started reading yet, both writes block forever. Doing
// the write and the read concurrently here makes this correct over both kinds of transport.
//
// Returns the OTHER side's decoded identity as a *PeerInfo (Reachable=true,
// RemoteStaticPubKey=s.PeerStaticKey, Latency left unset -- Probe fills that in). See identity.go
// for the exact frame layout built/parsed here and the (minimal) outgoing message we send.
//
// ctx's deadline (if any) bounds the wait for the peer's identity message; if ctx has no
// deadline, a 10-second timeout is applied, matching Tari's own
// `time::timeout(Duration::from_secs(10), ...)` (tari/comms/core/src/protocol/identity.rs).
func (s *Session) ExchangeIdentity(ctx context.Context) (*PeerInfo, error) {
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, identityExchangeTimeout)
		defer cancel()
	}

	ourMsgBytes, err := ourPeerIdentityMsgBytes(s.LocalStaticKeypair)
	if err != nil {
		return nil, err
	}
	outgoingFrame, err := encodeIdentityProtocolFrame(ourMsgBytes)
	if err != nil {
		return nil, fmt.Errorf("p2p: encoding outgoing identity message: %w", err)
	}

	sendErrCh := make(chan error, 1)
	go func() {
		sendErrCh <- s.SendFrame(outgoingFrame)
	}()

	type result struct {
		info *PeerInfo
		err  error
	}
	recvCh := make(chan result, 1)
	go func() {
		plaintext, err := s.ReceiveFrame()
		if err != nil {
			recvCh <- result{err: fmt.Errorf("p2p: receiving peer identity message: %w", err)}
			return
		}
		info, err := decodeIdentityProtocolFrame(plaintext)
		recvCh <- result{info: info, err: err}
	}()

	var recvResult result
	var recvDone bool
	var sendErr error
	var sendDone bool

	for !recvDone || !sendDone {
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("p2p: exchanging identity message: %w", ctx.Err())
		case sendErr = <-sendErrCh:
			sendDone = true
			if sendErr != nil {
				return nil, fmt.Errorf("p2p: sending identity message: %w", sendErr)
			}
		case recvResult = <-recvCh:
			recvDone = true
			if recvResult.err != nil {
				return nil, recvResult.err
			}
		}
	}

	recvResult.info.Reachable = true
	recvResult.info.RemoteStaticPubKey = append([]byte(nil), s.PeerStaticKey...)
	return recvResult.info, nil
}
