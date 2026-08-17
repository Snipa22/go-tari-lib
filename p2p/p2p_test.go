package p2p_test

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-lib/p2p"
)

// pipeConn adapts a net.Pipe() half (which has no deadline/wire-byte-write concept issues, but
// also no real TCP semantics) to satisfy net.Conn for InitiatorHandshake/ResponderHandshake. net
// .Pipe()'s net.Conn already implements the full interface, so no adaptation is actually needed
// -- this type alias exists purely for readability at call sites below.
type pipeConn = net.Conn

// TestInitiatorResponderNoiseXXAndIdentityExchange is the in-process two-peer test required by
// P2P_SPEC.md section 8 point 3. It uses net.Pipe() (an in-memory, synchronous, full-duplex
// net.Conn implementation) rather than loopback TCP, because:
//   - it needs no OS socket/port allocation (faster, no flakiness from port reuse/binding),
//   - InitiatorHandshake/ResponderHandshake/Session only ever require a net.Conn, and net.Pipe's
//     implementation satisfies that interface fully (Read/Write/Close/SetDeadline etc.),
//   - the one caveat is net.Pipe is *synchronous*: a Write blocks until the corresponding Read
//     consumes it. That's why both the initiator and responder sides run in their own goroutine
//     below -- a real TCP connection would work identically without that requirement, but
//     wouldn't need two goroutines to make progress on a single-process test the way net.Pipe
//     does.
func TestInitiatorResponderNoiseXXAndIdentityExchange(t *testing.T) {
	initiatorConn, responderConn := net.Pipe()
	defer initiatorConn.Close()
	defer responderConn.Close()

	initiatorStatic, err := p2p.GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating initiator static keypair: %v", err)
	}
	responderStatic, err := p2p.GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating responder static keypair: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	type handshakeResult struct {
		session *p2p.Session
		err     error
	}

	initiatorResultCh := make(chan handshakeResult, 1)
	responderResultCh := make(chan handshakeResult, 1)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		session, err := p2p.InitiatorHandshake(ctx, initiatorConn, initiatorStatic)
		initiatorResultCh <- handshakeResult{session: session, err: err}
	}()

	go func() {
		defer wg.Done()
		session, err := p2p.ResponderHandshake(ctx, responderConn, responderStatic)
		responderResultCh <- handshakeResult{session: session, err: err}
	}()

	wg.Wait()

	initiatorRes := <-initiatorResultCh
	responderRes := <-responderResultCh

	if initiatorRes.err != nil {
		t.Fatalf("initiator handshake failed: %v", initiatorRes.err)
	}
	if responderRes.err != nil {
		t.Fatalf("responder handshake failed: %v", responderRes.err)
	}

	initiatorSession := initiatorRes.session
	responderSession := responderRes.session
	defer initiatorSession.Close()
	defer responderSession.Close()

	// Each side's recovered peer static pubkey must match the other side's actual static
	// public key bytes.
	if !bytes.Equal(initiatorSession.PeerStaticKey, responderStatic.Public) {
		t.Fatalf("initiator recovered wrong peer static key:\n got  %x\n want %x", initiatorSession.PeerStaticKey, responderStatic.Public)
	}
	if !bytes.Equal(responderSession.PeerStaticKey, initiatorStatic.Public) {
		t.Fatalf("responder recovered wrong peer static key:\n got  %x\n want %x", responderSession.PeerStaticKey, initiatorStatic.Public)
	}

	// Now exchange identities on both sides concurrently (half-RTT: both write first, then
	// read -- see ExchangeIdentity's doc comment).
	type identityResult struct {
		info *p2p.PeerInfo
		err  error
	}
	initiatorIdentityCh := make(chan identityResult, 1)
	responderIdentityCh := make(chan identityResult, 1)

	var idWg sync.WaitGroup
	idWg.Add(2)

	go func() {
		defer idWg.Done()
		info, err := initiatorSession.ExchangeIdentity(ctx)
		initiatorIdentityCh <- identityResult{info: info, err: err}
	}()

	go func() {
		defer idWg.Done()
		info, err := responderSession.ExchangeIdentity(ctx)
		responderIdentityCh <- identityResult{info: info, err: err}
	}()

	idWg.Wait()

	initiatorIdentity := <-initiatorIdentityCh
	responderIdentity := <-responderIdentityCh

	if initiatorIdentity.err != nil {
		t.Fatalf("initiator ExchangeIdentity failed: %v", initiatorIdentity.err)
	}
	if responderIdentity.err != nil {
		t.Fatalf("responder ExchangeIdentity failed: %v", responderIdentity.err)
	}

	// The initiator receives the RESPONDER's identity, and vice versa. Both sides of this test
	// send the same minimal outgoing PeerIdentityMsg (see identity.go, ourPeerIdentityMsgBytes),
	// so both received identities should show the same shape.
	const wantUserAgent = "go-tari-lib-p2p-probe/0.1"

	if initiatorIdentity.info.UserAgent != wantUserAgent {
		t.Errorf("initiator received wrong user_agent from responder: got %q, want %q", initiatorIdentity.info.UserAgent, wantUserAgent)
	}
	if responderIdentity.info.UserAgent != wantUserAgent {
		t.Errorf("responder received wrong user_agent from initiator: got %q, want %q", responderIdentity.info.UserAgent, wantUserAgent)
	}
	if initiatorIdentity.info.Features != 0 {
		t.Errorf("initiator received wrong features from responder: got %d, want 0", initiatorIdentity.info.Features)
	}
	if responderIdentity.info.Features != 0 {
		t.Errorf("responder received wrong features from initiator: got %d, want 0", responderIdentity.info.Features)
	}
	if len(initiatorIdentity.info.Addresses) != 0 {
		t.Errorf("initiator received non-empty addresses from responder: %v", initiatorIdentity.info.Addresses)
	}
	if len(initiatorIdentity.info.SupportedProtocols) != 0 {
		t.Errorf("initiator received non-empty supported_protocols from responder: %v", initiatorIdentity.info.SupportedProtocols)
	}
	if initiatorIdentity.info.IdentitySignature != nil {
		t.Errorf("initiator received an identity_signature from responder, expected nil (we don't send one)")
	}
	if !initiatorIdentity.info.Reachable {
		t.Errorf("initiator's PeerInfo.Reachable should be true after a successful exchange")
	}
	if !bytes.Equal(initiatorIdentity.info.RemoteStaticPubKey, responderStatic.Public) {
		t.Errorf("initiator's PeerInfo.RemoteStaticPubKey does not match responder's static public key:\n got  %x\n want %x",
			initiatorIdentity.info.RemoteStaticPubKey, responderStatic.Public)
	}
	if !bytes.Equal(responderIdentity.info.RemoteStaticPubKey, initiatorStatic.Public) {
		t.Errorf("responder's PeerInfo.RemoteStaticPubKey does not match initiator's static public key:\n got  %x\n want %x",
			responderIdentity.info.RemoteStaticPubKey, initiatorStatic.Public)
	}
}

// TestProbeAgainstInProcessResponder exercises the top-level Probe() function end to end
// (P2P_SPEC.md section 7/8). Per section 8 point 5, this deliberately does NOT dial a real
// mainnet Tari node -- instead a loopback TCP listener runs our own minimal ResponderHandshake +
// ExchangeIdentity, and Probe() dials that. This exercises the exact same Probe() code path a
// live probe would use; only the listening peer is our own code instead of a real Tari node.
func TestProbeAgainstInProcessResponder(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting loopback listener: %v", err)
	}
	defer listener.Close()

	responderStatic, err := p2p.GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating responder static keypair: %v", err)
	}

	serverErrCh := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverErrCh <- err
			return
		}
		defer conn.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		session, err := p2p.ResponderHandshake(ctx, conn, responderStatic)
		if err != nil {
			serverErrCh <- err
			return
		}
		defer session.Close()

		if _, err := session.ExchangeIdentity(ctx); err != nil {
			serverErrCh <- err
			return
		}
		serverErrCh <- nil
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	info, err := p2p.Probe(ctx, listener.Addr().String())
	if err != nil {
		t.Fatalf("Probe failed: %v", err)
	}
	if err := <-serverErrCh; err != nil {
		t.Fatalf("in-process responder side failed: %v", err)
	}

	if !info.Reachable {
		t.Fatalf("expected Reachable=true")
	}
	if !bytes.Equal(info.RemoteStaticPubKey, responderStatic.Public) {
		t.Fatalf("Probe recovered wrong remote static key:\n got  %x\n want %x", info.RemoteStaticPubKey, responderStatic.Public)
	}
	const wantUserAgent = "go-tari-lib-p2p-probe/0.1"
	if info.UserAgent != wantUserAgent {
		t.Fatalf("Probe: UserAgent = %q, want %q", info.UserAgent, wantUserAgent)
	}
	if info.Latency <= 0 {
		t.Fatalf("expected a positive Latency, got %s", info.Latency)
	}
}

// TestProbeUnreachablePeerReturnsCleanError checks that Probe returns a normal error (not a
// panic) for an unreachable address, per P2P_SPEC.md section 7's "Returns a clean error (not
// panic) for unreachable/non-Tari peers" requirement.
func TestProbeUnreachablePeerReturnsCleanError(t *testing.T) {
	// Reserve then immediately close a loopback port so nothing is listening there, giving a
	// high-probability "connection refused" without depending on any external network access.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := listener.Addr().String()
	listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if _, err := p2p.Probe(ctx, addr); err == nil {
		t.Fatalf("expected Probe against an unreachable address to return an error")
	}
}
