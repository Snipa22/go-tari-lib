package p2p

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

// yamuxAdapterTestSessions completes a real Noise_XX handshake over an in-memory net.Pipe(),
// returning both sides' *Session -- the same pattern used by p2p_test.go's
// TestInitiatorResponderNoiseXXAndIdentityExchange and p2p/rpc/rpc_test.go's
// handshakeBothSides. Kept as an internal (package p2p, not p2p_test) helper here because these
// tests need to construct sessionReadWriteCloser directly, which is unexported.
func yamuxAdapterTestSessions(t *testing.T) (a, b *Session) {
	t.Helper()

	connA, connB := net.Pipe()
	t.Cleanup(func() { connA.Close(); connB.Close() })

	staticA, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating keypair A: %v", err)
	}
	staticB, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating keypair B: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type result struct {
		session *Session
		err     error
	}
	chA := make(chan result, 1)
	chB := make(chan result, 1)

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		s, err := InitiatorHandshake(ctx, connA, staticA)
		chA <- result{s, err}
	}()
	go func() {
		defer wg.Done()
		s, err := ResponderHandshake(ctx, connB, staticB)
		chB <- result{s, err}
	}()
	wg.Wait()

	resA := <-chA
	resB := <-chB
	if resA.err != nil {
		t.Fatalf("initiator handshake failed: %v", resA.err)
	}
	if resB.err != nil {
		t.Fatalf("responder handshake failed: %v", resB.err)
	}
	return resA.session, resB.session
}

// TestSessionReadWriteCloserWriteRoundTrip covers Write: a single Write call must produce
// exactly one Session.SendFrame call whose plaintext the peer receives byte-exact via a plain
// Session.ReceiveFrame call (no yamux involved here -- this isolates the adapter's Write
// behaviour from its Read-buffering behaviour, tested separately below; the full real-yamux
// end-to-end path is covered by p2p/rpc's yamux integration test).
func TestSessionReadWriteCloserWriteRoundTrip(t *testing.T) {
	sender, receiver := yamuxAdapterTestSessions(t)
	defer sender.Close()
	defer receiver.Close()

	adapter := newSessionReadWriteCloser(sender)

	payload := []byte("hello over a single write call")
	type writeResult struct {
		n   int
		err error
	}
	doneCh := make(chan writeResult, 1)
	go func() {
		n, err := adapter.Write(payload)
		doneCh <- writeResult{n, err}
	}()

	got, err := receiver.ReceiveFrame()
	if err != nil {
		t.Fatalf("receiving frame: %v", err)
	}
	res := <-doneCh
	if res.err != nil {
		t.Fatalf("adapter.Write: %v", res.err)
	}
	if res.n != len(payload) {
		t.Fatalf("adapter.Write returned n=%d, want %d", res.n, len(payload))
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("received %q, want %q", got, payload)
	}
}

// TestSessionReadWriteCloserReadExactlyOneFrame covers the simplest Read case: the caller's
// buffer is large enough to hold the entire Noise transport frame in a single Read call, so no
// buffering across calls is needed.
func TestSessionReadWriteCloserReadExactlyOneFrame(t *testing.T) {
	sender, receiver := yamuxAdapterTestSessions(t)
	defer sender.Close()
	defer receiver.Close()

	adapter := newSessionReadWriteCloser(receiver)

	payload := []byte("exactly one frame, one read call")
	sendErrCh := make(chan error, 1)
	go func() { sendErrCh <- sender.SendFrame(payload) }()

	buf := make([]byte, len(payload))
	n, err := adapter.Read(buf)
	if err != nil {
		t.Fatalf("adapter.Read: %v", err)
	}
	if err := <-sendErrCh; err != nil {
		t.Fatalf("sender.SendFrame: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("Read returned n=%d, want %d", n, len(payload))
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("Read returned %q, want %q", buf[:n], payload)
	}
}

// TestSessionReadWriteCloserReadBufferSmallerThanFrame covers the buffering case this adapter
// exists for: the caller's buffer is smaller than one Noise transport frame's worth of data, so
// the frame must be drained across multiple Read calls, with leftover bytes preserved between
// calls (this is exactly what a real yamux.Session's internal reader does to the underlying
// io.ReadWriteCloser -- it does not know or care how big the frames underneath happen to be).
func TestSessionReadWriteCloserReadBufferSmallerThanFrame(t *testing.T) {
	sender, receiver := yamuxAdapterTestSessions(t)
	defer sender.Close()
	defer receiver.Close()

	adapter := newSessionReadWriteCloser(receiver)

	payload := []byte("0123456789ABCDEF") // 16 bytes
	sendErrCh := make(chan error, 1)
	go func() { sendErrCh <- sender.SendFrame(payload) }()

	var got []byte
	small := make([]byte, 5) // deliberately smaller than len(payload); requires multiple Read calls
	reads := 0
	for len(got) < len(payload) {
		n, err := adapter.Read(small)
		if err != nil {
			t.Fatalf("adapter.Read: %v", err)
		}
		if n == 0 {
			t.Fatalf("adapter.Read returned n=0 with no error")
		}
		if n > len(small) {
			t.Fatalf("adapter.Read returned n=%d > len(buf)=%d", n, len(small))
		}
		got = append(got, small[:n]...)
		reads++
	}
	if err := <-sendErrCh; err != nil {
		t.Fatalf("sender.SendFrame: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("drained %q, want %q", got, payload)
	}
	if reads < 2 {
		t.Fatalf("expected draining a %d-byte frame through a %d-byte buffer to take at least 2 Read calls, took %d", len(payload), len(small), reads)
	}
}

// TestSessionReadWriteCloserReadAcrossTwoFrames covers draining a small leftover buffer from one
// frame, then correctly moving on to fetch and drain a second, subsequent frame -- i.e. that the
// "drain leftover before calling ReceiveFrame again" logic doesn't get stuck re-reading the same
// frame or skip a frame boundary.
func TestSessionReadWriteCloserReadAcrossTwoFrames(t *testing.T) {
	sender, receiver := yamuxAdapterTestSessions(t)
	defer sender.Close()
	defer receiver.Close()

	adapter := newSessionReadWriteCloser(receiver)

	first := []byte("first-frame-payload")
	second := []byte("second-frame-payload")
	sendErrCh := make(chan error, 1)
	go func() {
		if err := sender.SendFrame(first); err != nil {
			sendErrCh <- err
			return
		}
		sendErrCh <- sender.SendFrame(second)
	}()

	want := append(append([]byte{}, first...), second...)
	var got []byte
	buf := make([]byte, 7)
	for len(got) < len(want) {
		n, err := adapter.Read(buf)
		if err != nil {
			t.Fatalf("adapter.Read: %v", err)
		}
		got = append(got, buf[:n]...)
	}
	if err := <-sendErrCh; err != nil {
		t.Fatalf("sender.SendFrame: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("drained %q, want %q", got, want)
	}
}

// TestSessionReadWriteCloserClose covers Close: it must close the underlying Session (proven by
// a subsequent ReceiveFrame call on the peer failing, since the pipe is now closed).
func TestSessionReadWriteCloserClose(t *testing.T) {
	a, b := yamuxAdapterTestSessions(t)
	defer b.Close()

	adapter := newSessionReadWriteCloser(a)
	if err := adapter.Close(); err != nil {
		t.Fatalf("adapter.Close: %v", err)
	}

	if _, err := b.ReceiveFrame(); err == nil {
		t.Fatalf("expected b.ReceiveFrame to fail after adapter.Close() closed the peer connection")
	}
}
