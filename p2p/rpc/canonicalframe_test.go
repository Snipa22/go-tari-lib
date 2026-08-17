package rpc

import (
	"bytes"
	"testing"
)

func TestCanonicalFrameRoundTrip(t *testing.T) {
	cases := [][]byte{
		{},
		[]byte("hello"),
		bytes.Repeat([]byte{0xAB}, 1024),
	}
	for _, payload := range cases {
		frame := EncodeCanonicalFrame(payload)
		if len(frame) != 4+len(payload) {
			t.Fatalf("EncodeCanonicalFrame(%d bytes): frame length = %d, want %d", len(payload), len(frame), 4+len(payload))
		}
		got, err := DecodeCanonicalFrame(frame)
		if err != nil {
			t.Fatalf("DecodeCanonicalFrame: %v", err)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("round-trip mismatch: got %x, want %x", got, payload)
		}
	}
}

func TestDecodeCanonicalFrameTooShort(t *testing.T) {
	if _, err := DecodeCanonicalFrame([]byte{0x00, 0x00}); err == nil {
		t.Fatalf("expected an error for a frame shorter than the length prefix")
	}
}

func TestDecodeCanonicalFrameLengthMismatch(t *testing.T) {
	// Declares a payload of 10 bytes but only supplies 3.
	frame := []byte{0x00, 0x00, 0x00, 0x0A, 0x01, 0x02, 0x03}
	if _, err := DecodeCanonicalFrame(frame); err == nil {
		t.Fatalf("expected an error for a declared-length/actual-length mismatch")
	}
}
