package p2p

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/yamux"

	rpcpkg "github.com/Snipa22/go-tari-lib/p2p/rpc"
)

// TestServeObservabilityCallbacks exercises every observability callback ResponderConfig exposes
// (OnConnectionAccepted, OnHandshakeResult, OnIdentityExchangeResult, OnGetPeersServed,
// OnSubstreamProtocolDeclined -- see responder.go's doc comments), confirming each fires exactly
// when its doc comment says it does. This lives in package p2p (not p2p_test) specifically to
// reach newSessionReadWriteCloser for the "declined protocol" half below, which needs to open a
// raw Yamux substream and negotiate an unsupported protocol id directly -- something no exported
// helper in this package does today (ProbeGetPeersWithOptions only ever negotiates `t/dht/1`).
func TestServeObservabilityCallbacks(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting loopback listener: %v", err)
	}
	defer listener.Close()

	responderStatic, err := GenerateRistrettoKeypair()
	if err != nil {
		t.Fatalf("generating responder static keypair: %v", err)
	}

	var mu sync.Mutex
	var (
		connectionAccepted   int
		handshakeResults     []bool
		identityResults      []bool
		getPeersServedCounts []int
		declinedProtocols    [][]byte
	)

	cfg := ResponderConfig{
		StaticKeypair: responderStatic,
		OurFeatures:   FeaturesCommunicationNode,
		// PeerListProvider deliberately left nil -- Serve/knownPeers already handles that as
		// "serve an empty list" (see knownPeers' doc comment), which is exactly what this test
		// wants for its OnGetPeersServed(peerCount=0) assertion below.
		Logf: t.Logf,
		OnConnectionAccepted: func(remoteAddr net.Addr) {
			mu.Lock()
			defer mu.Unlock()
			connectionAccepted++
		},
		OnHandshakeResult: func(remoteAddr net.Addr, success bool) {
			mu.Lock()
			defer mu.Unlock()
			handshakeResults = append(handshakeResults, success)
		},
		OnIdentityExchangeResult: func(remoteAddr net.Addr, success bool) {
			mu.Lock()
			defer mu.Unlock()
			identityResults = append(identityResults, success)
		},
		OnGetPeersServed: func(remoteAddr net.Addr, peerCount int) {
			mu.Lock()
			defer mu.Unlock()
			getPeersServedCounts = append(getPeersServedCounts, peerCount)
		},
		OnSubstreamProtocolDeclined: func(remoteAddr net.Addr, protocol []byte) {
			mu.Lock()
			defer mu.Unlock()
			declinedProtocols = append(declinedProtocols, append([]byte(nil), protocol...))
		},
	}

	serveCtx, serveCancel := context.WithCancel(context.Background())
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- Serve(serveCtx, listener, cfg)
	}()
	defer func() {
		serveCancel()
		listener.Close()
		<-serveErrCh
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Connection 1: a normal ProbeGetPeersWithOptions round trip -- exercises accept, a
	// successful handshake, a successful identity exchange, and a successful (empty, since
	// PeerListProvider is nil) get_peers response.
	if _, err := ProbeGetPeersWithOptions(ctx, listener.Addr().String(), rpcpkg.GetPeersRequest{N: 50}, ProbeOptions{}); err != nil {
		t.Fatalf("ProbeGetPeersWithOptions: %v", err)
	}

	// Connection 2: dial + handshake + identity exchange manually, then open a raw Yamux
	// substream and negotiate an UNSUPPORTED protocol id directly (rpcpkg.NegotiateProtocol),
	// exercising OnSubstreamProtocolDeclined -- something ProbeGetPeersWithOptions can't do
	// since it always negotiates the supported t/dht/1 protocol.
	func() {
		conn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			t.Fatalf("dialing responder: %v", err)
		}
		defer conn.Close()

		clientStatic, err := GenerateRistrettoKeypair()
		if err != nil {
			t.Fatalf("generating client static keypair: %v", err)
		}

		session, err := InitiatorHandshake(ctx, conn, clientStatic, defaultNetworkWireByte)
		if err != nil {
			t.Fatalf("InitiatorHandshake: %v", err)
		}
		defer session.Close()

		if _, err := session.ExchangeIdentity(ctx); err != nil {
			t.Fatalf("ExchangeIdentity: %v", err)
		}

		adapter := newSessionReadWriteCloser(session)
		yamuxSession, err := yamux.Client(adapter, nil)
		if err != nil {
			t.Fatalf("establishing Yamux client session: %v", err)
		}
		defer yamuxSession.Close()

		stream, err := yamuxSession.Open()
		if err != nil {
			t.Fatalf("opening Yamux substream: %v", err)
		}
		defer stream.Close()

		transport := rpcpkg.NewStreamTransport(stream)
		wantProtocol := []byte("t/msg/0.1")
		err = rpcpkg.NegotiateProtocol(transport, wantProtocol)
		if err == nil {
			t.Fatalf("expected NegotiateProtocol to fail for an unsupported protocol")
		}
		if !errors.Is(err, rpcpkg.ErrProtocolNotSupported) {
			t.Fatalf("expected errors.Is(err, rpcpkg.ErrProtocolNotSupported), got: %v", err)
		}
	}()

	// Give the responder's own goroutines (which run concurrently with the calls above
	// returning) a moment to invoke their callbacks -- OnSubstreamProtocolDeclined in
	// particular fires from handleResponderSubstream after NegotiateProtocolInbound replies on
	// the wire, which races with this test's own NegotiateProtocol call returning.
	deadline := time.Now().Add(5 * time.Second)
	for {
		mu.Lock()
		done := connectionAccepted >= 2 && len(handshakeResults) >= 2 && len(identityResults) >= 2 &&
			len(getPeersServedCounts) >= 1 && len(declinedProtocols) >= 1
		mu.Unlock()
		if done || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	mu.Lock()
	defer mu.Unlock()

	if connectionAccepted != 2 {
		t.Errorf("OnConnectionAccepted fired %d times, want 2", connectionAccepted)
	}
	if len(handshakeResults) != 2 {
		t.Fatalf("OnHandshakeResult fired %d times, want 2", len(handshakeResults))
	}
	for i, ok := range handshakeResults {
		if !ok {
			t.Errorf("OnHandshakeResult[%d] = false, want true (both connections' handshakes succeed)", i)
		}
	}
	if len(identityResults) != 2 {
		t.Fatalf("OnIdentityExchangeResult fired %d times, want 2", len(identityResults))
	}
	for i, ok := range identityResults {
		if !ok {
			t.Errorf("OnIdentityExchangeResult[%d] = false, want true (both connections' identity exchanges succeed)", i)
		}
	}
	if len(getPeersServedCounts) != 1 {
		t.Fatalf("OnGetPeersServed fired %d times, want 1 (only connection 1 completed get_peers)", len(getPeersServedCounts))
	}
	if getPeersServedCounts[0] != 0 {
		t.Errorf("OnGetPeersServed peerCount = %d, want 0 (nil PeerListProvider)", getPeersServedCounts[0])
	}
	if len(declinedProtocols) != 1 {
		t.Fatalf("OnSubstreamProtocolDeclined fired %d times, want 1", len(declinedProtocols))
	}
	if string(declinedProtocols[0]) != "t/msg/0.1" {
		t.Errorf("OnSubstreamProtocolDeclined protocol = %q, want %q", declinedProtocols[0], "t/msg/0.1")
	}
}
