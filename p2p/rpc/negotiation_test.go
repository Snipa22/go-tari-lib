package rpc

import "testing"

func TestEncodeNegotiationFrameTooLong(t *testing.T) {
	longProtocol := make([]byte, 256)
	if _, err := encodeNegotiationFrame(negotiationFlagNone, longProtocol); err == nil {
		t.Fatalf("expected an error for a protocol id longer than 255 bytes")
	}
}

func TestDecodeNegotiationFrameTooShort(t *testing.T) {
	if _, _, err := decodeNegotiationFrame([]byte{0x01}); err == nil {
		t.Fatalf("expected an error for a frame shorter than the 2-byte header")
	}
}

func TestEncodeDecodeNegotiationFrameRoundTrip(t *testing.T) {
	protocolID := []byte("t/blksync/1")
	frame, err := encodeNegotiationFrame(negotiationFlagNone, protocolID)
	if err != nil {
		t.Fatalf("encodeNegotiationFrame: %v", err)
	}
	flags, gotProtocol, err := decodeNegotiationFrame(frame)
	if err != nil {
		t.Fatalf("decodeNegotiationFrame: %v", err)
	}
	if flags != negotiationFlagNone {
		t.Fatalf("flags = 0x%x, want 0x%x", flags, negotiationFlagNone)
	}
	if !bytesEqual(gotProtocol, protocolID) {
		t.Fatalf("protocol id = %q, want %q", gotProtocol, protocolID)
	}
}
