package rpc

import (
	"bytes"
	"net"
	"testing"
)

// TestStreamTransportSendFrameAddsNoExtraFraming is the core correctness property of this file:
// SendFrame must write payload to the stream completely unmodified -- no additional length
// prefix of any kind, for either message kind (payload here stands in for either an already
// negotiation-framed or already canonical-framed message; SendFrame doesn't care which, since it
// never adds framing of its own regardless).
func TestStreamTransportSendFrameAddsNoExtraFraming(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	transport := NewStreamTransport(clientConn)

	payload := []byte{0x03, negotiationFlagNone, 't', '/', 'x'} // a hand-built negotiation frame
	doneCh := make(chan error, 1)
	go func() { doneCh <- transport.SendFrame(payload) }()

	got := make([]byte, len(payload))
	if _, err := readFull(serverConn, got); err != nil {
		t.Fatalf("reading raw bytes off the wire: %v", err)
	}
	if err := <-doneCh; err != nil {
		t.Fatalf("SendFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("raw bytes on the wire = %x, want exactly payload %x with no extra framing", got, payload)
	}
}

// readFull is a tiny io.ReadFull stand-in kept local to this test file to avoid importing "io"
// just for this one helper call (used only to read a known-fixed number of raw bytes off a
// net.Pipe conn in the test above).
func readFull(r interface{ Read([]byte) (int, error) }, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := r.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// TestStreamTransportReceiveFrameNegotiationMode covers ReceiveFrame's default (pre-
// BeginCanonicalFraming) behaviour: parsing a self-delimiting negotiation frame -- 2-byte header
// (length + flags) then exactly `length` more body bytes -- written directly to the stream with
// no outer wrapper, exactly matching what a real negotiation.rs peer (or this package's own
// encodeNegotiationFrame, fed straight to a plain net.Conn) would put on the wire.
func TestStreamTransportReceiveFrameNegotiationMode(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	transport := NewStreamTransport(serverConn)

	protocolID := []byte("t/blksync/1")
	wireFrame, err := encodeNegotiationFrame(negotiationFlagNone, protocolID)
	if err != nil {
		t.Fatalf("encodeNegotiationFrame: %v", err)
	}

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(wireFrame) // written raw, exactly as a real peer would
		writeErrCh <- err
	}()

	got, err := transport.ReceiveFrame()
	if err != nil {
		t.Fatalf("ReceiveFrame: %v", err)
	}
	if err := <-writeErrCh; err != nil {
		t.Fatalf("writing raw frame: %v", err)
	}
	if !bytes.Equal(got, wireFrame) {
		t.Fatalf("ReceiveFrame returned %x, want exactly the raw wire frame %x", got, wireFrame)
	}

	flags, gotProtocolID, err := decodeNegotiationFrame(got)
	if err != nil {
		t.Fatalf("decodeNegotiationFrame(ReceiveFrame's output): %v", err)
	}
	if flags != negotiationFlagNone {
		t.Fatalf("decoded flags = %#x, want %#x", flags, negotiationFlagNone)
	}
	if !bytes.Equal(gotProtocolID, protocolID) {
		t.Fatalf("decoded protocol id = %q, want %q", gotProtocolID, protocolID)
	}
}

// TestStreamTransportReceiveFrameCanonicalModeAfterSwitch covers the BeginCanonicalFraming
// transition: before it's called, ReceiveFrame parses negotiation frames; after it's called,
// ReceiveFrame parses canonical (u32-BE length-prefixed) frames instead -- both directly off the
// raw stream with no additional wrapper, matching EncodeCanonicalFrame/DecodeCanonicalFrame's
// own already-self-delimiting wire format exactly.
func TestStreamTransportReceiveFrameCanonicalModeAfterSwitch(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	transport := NewStreamTransport(serverConn)
	BeginCanonicalFraming(transport)

	payload := []byte("some protobuf-shaped bytes, contents don't matter for this test")
	wireFrame := EncodeCanonicalFrame(payload)

	writeErrCh := make(chan error, 1)
	go func() {
		_, err := clientConn.Write(wireFrame) // written raw, exactly as a real peer would
		writeErrCh <- err
	}()

	got, err := transport.ReceiveFrame()
	if err != nil {
		t.Fatalf("ReceiveFrame: %v", err)
	}
	if err := <-writeErrCh; err != nil {
		t.Fatalf("writing raw frame: %v", err)
	}
	if !bytes.Equal(got, wireFrame) {
		t.Fatalf("ReceiveFrame returned %x, want exactly the raw wire frame %x", got, wireFrame)
	}

	gotPayload, err := DecodeCanonicalFrame(got)
	if err != nil {
		t.Fatalf("DecodeCanonicalFrame(ReceiveFrame's output): %v", err)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("decoded payload = %q, want %q", gotPayload, payload)
	}
}

// TestStreamTransportBeginCanonicalFramingIsNoOpForOtherTransports covers
// BeginCanonicalFraming's documented no-op behaviour for any Transport implementation that
// doesn't need the negotiation/canonical mode distinction (i.e. doesn't implement
// canonicalFramingSwitch) -- it must not panic or otherwise misbehave.
func TestStreamTransportBeginCanonicalFramingIsNoOpForOtherTransports(t *testing.T) {
	BeginCanonicalFraming(fakeTransport{}) // must not panic
}

type fakeTransport struct{}

func (fakeTransport) SendFrame([]byte) error        { return nil }
func (fakeTransport) ReceiveFrame() ([]byte, error) { return nil, nil }

// TestStreamTransportRoundTripBothModesOnOneStream covers negotiation-then-canonical framing
// sharing one stream sequentially -- the exact scenario streamTransport exists for -- by driving
// SendFrame/ReceiveFrame on TWO streamTransport instances wrapping the two ends of one
// net.Pipe(), one negotiation-framed round trip followed immediately by one canonical-framed
// round trip on the same underlying connection, with BeginCanonicalFraming called on both ends
// in between (mirroring what GetChainMetadata does on the client side and what
// serveGetChainMetadataOverStream-style responders must do on the server side).
func TestStreamTransportRoundTripBothModesOnOneStream(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	client := NewStreamTransport(clientConn)
	server := NewStreamTransport(serverConn)

	negotiationFrame, err := encodeNegotiationFrame(negotiationFlagNone, BlockSyncProtocolID)
	if err != nil {
		t.Fatalf("encodeNegotiationFrame: %v", err)
	}

	sendErrCh := make(chan error, 1)
	go func() { sendErrCh <- client.SendFrame(negotiationFrame) }()

	gotNegotiation, err := server.ReceiveFrame()
	if err != nil {
		t.Fatalf("server.ReceiveFrame (negotiation phase): %v", err)
	}
	if err := <-sendErrCh; err != nil {
		t.Fatalf("client.SendFrame (negotiation phase): %v", err)
	}
	if !bytes.Equal(gotNegotiation, negotiationFrame) {
		t.Fatalf("negotiation phase: got %x, want %x", gotNegotiation, negotiationFrame)
	}

	BeginCanonicalFraming(client)
	BeginCanonicalFraming(server)

	canonicalPayload := []byte("an RpcSession or RpcRequest's marshalled bytes, in spirit")
	canonicalFrame := EncodeCanonicalFrame(canonicalPayload)

	go func() { sendErrCh <- client.SendFrame(canonicalFrame) }()

	gotCanonical, err := server.ReceiveFrame()
	if err != nil {
		t.Fatalf("server.ReceiveFrame (canonical phase): %v", err)
	}
	if err := <-sendErrCh; err != nil {
		t.Fatalf("client.SendFrame (canonical phase): %v", err)
	}
	if !bytes.Equal(gotCanonical, canonicalFrame) {
		t.Fatalf("canonical phase: got %x, want %x", gotCanonical, canonicalFrame)
	}
}
