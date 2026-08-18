package p2p

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

// firstByteWrittenByProbe starts a throwaway raw TCP listener that accepts exactly one
// connection, reads exactly its first byte (before any Noise/handshake logic runs on either
// side), records it, then closes the connection -- and calls probe(ctx, addr) against that
// listener's address, returning the captured byte.
//
// probe is expected to return an error in this setup: the raw listener never completes a real
// Noise_XX handshake (it just reads one byte and closes), so InitiatorHandshake's
// post-network-byte Noise exchange will fail once the connection closes out from under it.
// That's expected and deliberately ignored here -- this helper only cares about the one raw byte
// written to the wire before any of that happens, which is exactly the behavior under test (see
// ProbeOptions.NetworkByte in p2p/socks.go, and the network-wire-byte-first ordering documented
// on InitiatorHandshake in p2p/handshake.go, itself sourced from
// tari/comms/core/src/connection_manager/dialer.rs's `dial_peer`).
func firstByteWrittenByProbe(t *testing.T, probe func(ctx context.Context, addr string) error) byte {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("starting raw loopback listener: %v", err)
	}
	defer listener.Close()

	byteCh := make(chan byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		buf := make([]byte, 1)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		byteCh <- buf[0]
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Expected to fail (see doc comment above) -- only the byte captured on the wire matters.
	_ = probe(ctx, listener.Addr().String())

	select {
	case b := <-byteCh:
		return b
	case <-time.After(5 * time.Second):
		t.Fatalf("timed out waiting for the raw listener to capture the first byte written to the wire")
		return 0
	}
}

// TestProbeZeroConfigWritesMainNetNetworkByte is the critical no-regression test for this
// change: Probe (zero-config) and ProbeWithOptions with an explicit zero-value ProbeOptions must
// both still write exactly 0x00 (NetworkByteMainNet == defaultNetworkWireByte) as the very first
// byte on the wire, matching this package's pre-existing behavior before
// ProbeOptions.NetworkByte existed (source: tari/comms/core/src/protocol/network_info.rs,
// NodeNetworkInfo.network_wire_byte's `#[derive(Default)]` -> 0x00, i.e. MainNet).
func TestProbeZeroConfigWritesMainNetNetworkByte(t *testing.T) {
	t.Run("Probe", func(t *testing.T) {
		got := firstByteWrittenByProbe(t, func(ctx context.Context, addr string) error {
			_, err := Probe(ctx, addr)
			return err
		})
		if got != NetworkByteMainNet {
			t.Fatalf("Probe wrote network byte 0x%x, want 0x%x (NetworkByteMainNet)", got, NetworkByteMainNet)
		}
		if got != defaultNetworkWireByte {
			t.Fatalf("Probe wrote network byte 0x%x, want 0x%x (defaultNetworkWireByte)", got, defaultNetworkWireByte)
		}
	})

	t.Run("ProbeWithOptions explicit zero value", func(t *testing.T) {
		got := firstByteWrittenByProbe(t, func(ctx context.Context, addr string) error {
			_, err := ProbeWithOptions(ctx, addr, ProbeOptions{})
			return err
		})
		if got != NetworkByteMainNet {
			t.Fatalf("ProbeWithOptions(ProbeOptions{}) wrote network byte 0x%x, want 0x%x (NetworkByteMainNet)", got, NetworkByteMainNet)
		}
	})
}

// TestProbeWithOptionsNonDefaultNetworkByteIsWrittenToWire covers ProbeOptions.NetworkByte
// actually being threaded through to InitiatorHandshake and written as the first raw byte on the
// wire, for a real non-default Tari network value (Esmeralda, 0x26 -- source:
// tari/common/src/configuration/network.rs).
func TestProbeWithOptionsNonDefaultNetworkByteIsWrittenToWire(t *testing.T) {
	got := firstByteWrittenByProbe(t, func(ctx context.Context, addr string) error {
		_, err := ProbeWithOptions(ctx, addr, ProbeOptions{NetworkByte: NetworkByteEsmeralda})
		return err
	})
	if got != NetworkByteEsmeralda {
		t.Fatalf("ProbeWithOptions(ProbeOptions{NetworkByte: NetworkByteEsmeralda}) wrote network byte 0x%x, want 0x%x", got, NetworkByteEsmeralda)
	}
}

// TestProbeChainMetadataWithOptionsNetworkByteThreadsThrough is
// TestProbeWithOptionsNonDefaultNetworkByteIsWrittenToWire's equivalent for
// ProbeChainMetadataWithOptions, proving opts.NetworkByte is threaded through to
// InitiatorHandshake on that call path too (p2p/chainmetadata_probe.go).
func TestProbeChainMetadataWithOptionsNetworkByteThreadsThrough(t *testing.T) {
	got := firstByteWrittenByProbe(t, func(ctx context.Context, addr string) error {
		_, err := ProbeChainMetadataWithOptions(ctx, addr, ProbeOptions{NetworkByte: NetworkByteEsmeralda})
		return err
	})
	if got != NetworkByteEsmeralda {
		t.Fatalf("ProbeChainMetadataWithOptions(ProbeOptions{NetworkByte: NetworkByteEsmeralda}) wrote network byte 0x%x, want 0x%x", got, NetworkByteEsmeralda)
	}
}

// TestProbeGetPeersWithOptionsNetworkByteThreadsThrough is
// TestProbeWithOptionsNonDefaultNetworkByteIsWrittenToWire's equivalent for
// ProbeGetPeersWithOptions, proving opts.NetworkByte is threaded through to InitiatorHandshake on
// that call path too (p2p/getpeers_probe.go).
func TestProbeGetPeersWithOptionsNetworkByteThreadsThrough(t *testing.T) {
	got := firstByteWrittenByProbe(t, func(ctx context.Context, addr string) error {
		_, err := ProbeGetPeersWithOptions(ctx, addr, DefaultGetPeersRequest(), ProbeOptions{NetworkByte: NetworkByteEsmeralda})
		return err
	})
	if got != NetworkByteEsmeralda {
		t.Fatalf("ProbeGetPeersWithOptions(..., ProbeOptions{NetworkByte: NetworkByteEsmeralda}) wrote network byte 0x%x, want 0x%x", got, NetworkByteEsmeralda)
	}
}
