package p2p

import "fmt"

// sessionReadWriteCloser adapts a *Session's frame-oriented SendFrame/ReceiveFrame API to the
// plain io.ReadWriteCloser (byte-stream) interface that github.com/hashicorp/yamux requires as
// the underlying transport for a yamux.Session (see yamux.Client/yamux.Server, both of which take
// an io.ReadWriteCloser).
//
// Why this exists / where it sits in the stack (source: real Tari Rust
// comms/core/src/multiplexing/yamux.rs + comms/core/src/connection_manager/peer_connection.rs):
// Yamux's own multiplexed byte stream is carried AS THE PLAINTEXT PAYLOAD of Noise transport
// frames -- i.e. yamux sits ON TOP of the already-encrypted Noise session, not instead of it.
// Concretely: yamux.Session, wrapping this adapter, will Write() arbitrary-length byte chunks of
// its own internal framing protocol; each Write call here becomes exactly one
// Session.SendFrame call (one Noise transport message / one u16-BE Noise frame on the wire).
// Symmetrically, each Session.ReceiveFrame call yields one Noise transport message's worth of
// plaintext, which is the yamux byte stream's next chunk -- but yamux's Read calls, per the
// io.Reader contract, may ask for fewer bytes than a single ReceiveFrame call returns, so
// leftover bytes from one ReceiveFrame call are buffered here and drained on subsequent Read
// calls before pulling a new frame off the wire.
type sessionReadWriteCloser struct {
	session *Session

	// readBuf holds bytes already received from session.ReceiveFrame() but not yet returned to
	// a caller of Read -- i.e. the leftover tail of the most recently received Noise transport
	// frame, whenever the caller's buffer was smaller than the whole frame.
	readBuf []byte
}

// newSessionReadWriteCloser constructs a sessionReadWriteCloser wrapping session.
func newSessionReadWriteCloser(session *Session) *sessionReadWriteCloser {
	return &sessionReadWriteCloser{session: session}
}

// Write sends p as a single Noise transport frame (one Session.SendFrame call per Write call).
// On success, the full length of p is reported written, matching the io.Writer contract (either
// the whole frame gets encrypted+written or an error is returned -- SendFrame has no partial-
// write mode).
func (s *sessionReadWriteCloser) Write(p []byte) (int, error) {
	if err := s.session.SendFrame(p); err != nil {
		return 0, fmt.Errorf("p2p: yamux adapter: sending frame: %w", err)
	}
	return len(p), nil
}

// Read fills p with up to len(p) bytes, first draining any leftover bytes buffered from a
// previous Session.ReceiveFrame call before calling ReceiveFrame again. This is necessary
// because a single Noise transport frame (as returned by ReceiveFrame) may carry more bytes than
// the caller's buffer p can hold in one Read call -- ordinary io.Reader semantics permit (and
// yamux's own internal reader relies on) returning fewer bytes than requested and being called
// again for the rest, rather than requiring the whole frame to fit in one Read call.
func (s *sessionReadWriteCloser) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// Loop rather than a single ReceiveFrame call: a zero-length Noise transport frame is legal
	// (see readFrame's doc comment in frame.go) but carries no bytes for the caller, and
	// io.Reader's contract discourages returning (0, nil) -- so skip over any empty frames
	// rather than surfacing a no-op read to yamux's own reader.
	for len(s.readBuf) == 0 {
		frame, err := s.session.ReceiveFrame()
		if err != nil {
			return 0, fmt.Errorf("p2p: yamux adapter: receiving frame: %w", err)
		}
		s.readBuf = frame
	}

	n := copy(p, s.readBuf)
	s.readBuf = s.readBuf[n:]
	return n, nil
}

// Close closes the underlying Session (and, transitively, its net.Conn).
func (s *sessionReadWriteCloser) Close() error {
	return s.session.Close()
}
