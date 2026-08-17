package rpc_test

import (
	"errors"
	"testing"

	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	"github.com/Snipa22/go-tari-lib/p2p/rpc"
)

// These tests exercise NegotiateProtocol/NegotiateProtocolInbound and
// PerformSessionHandshake/PerformSessionHandshakeResponder/RejectSessionHandshakeResponder --
// all exported symbols of package rpc -- against a real Noise_XX-handshaked *p2p.Session pair
// (see handshakeBothSides in rpc_test.go). This lives in the external rpc_test package (rather
// than package rpc) specifically to avoid an import cycle: package p2p (via
// p2p/chainmetadata_probe.go) imports package rpc, so package rpc's own internal test files
// must not import package p2p.

func TestNegotiateProtocolSuccess(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	protocolID := []byte("t/blksync/1")

	responderErrCh := make(chan error, 1)
	go func() {
		_, err := rpc.NegotiateProtocolInbound(server, [][]byte{protocolID})
		responderErrCh <- err
	}()

	if err := rpc.NegotiateProtocol(client, protocolID); err != nil {
		t.Fatalf("NegotiateProtocol: %v", err)
	}
	if err := <-responderErrCh; err != nil {
		t.Fatalf("NegotiateProtocolInbound: %v", err)
	}
}

func TestNegotiateProtocolNotSupported(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	protocolID := []byte("t/blksync/1")

	responderErrCh := make(chan error, 1)
	go func() {
		_, err := rpc.NegotiateProtocolInbound(server, [][]byte{[]byte("t/other/1")})
		responderErrCh <- err
	}()

	err := rpc.NegotiateProtocol(client, protocolID)
	if err == nil {
		t.Fatalf("expected NegotiateProtocol to fail when the peer doesn't support the protocol")
	}
	if !errors.Is(err, rpc.ErrProtocolNotSupported) {
		t.Fatalf("expected errors.Is(err, rpc.ErrProtocolNotSupported), got: %v", err)
	}
	if respErr := <-responderErrCh; respErr == nil {
		t.Fatalf("expected NegotiateProtocolInbound to also report an error for the unsupported protocol")
	}
}

func TestPerformSessionHandshakeAccepted(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	responderErrCh := make(chan error, 1)
	go func() {
		responderErrCh <- rpc.PerformSessionHandshakeResponder(server)
	}()

	version, err := rpc.PerformSessionHandshake(client)
	if err != nil {
		t.Fatalf("PerformSessionHandshake: %v", err)
	}
	if version != rpc.SupportedRPCVersion {
		t.Fatalf("negotiated RPC version = %d, want %d", version, rpc.SupportedRPCVersion)
	}
	if err := <-responderErrCh; err != nil {
		t.Fatalf("PerformSessionHandshakeResponder: %v", err)
	}
}

func TestPerformSessionHandshakeRejected(t *testing.T) {
	client, server := handshakeBothSides(t)
	defer client.Close()
	defer server.Close()

	const wantReason = pb.RpcSessionReply_HANDSHAKE_REJECT_REASON_UNSUPPORTED_VERSION

	responderErrCh := make(chan error, 1)
	go func() {
		responderErrCh <- rpc.RejectSessionHandshakeResponder(server, wantReason)
	}()

	_, err := rpc.PerformSessionHandshake(client)
	if err == nil {
		t.Fatalf("expected PerformSessionHandshake to fail when the peer rejects the handshake")
	}
	var rejected *rpc.HandshakeRejectedError
	if !errors.As(err, &rejected) {
		t.Fatalf("expected a *rpc.HandshakeRejectedError, got: %v (%T)", err, err)
	}
	if rejected.Reason != wantReason {
		t.Fatalf("HandshakeRejectedError.Reason = %v, want %v", rejected.Reason, wantReason)
	}
	if err := <-responderErrCh; err != nil {
		t.Fatalf("RejectSessionHandshakeResponder: %v", err)
	}
}
