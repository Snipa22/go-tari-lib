package p2p

import (
	"bytes"
	"encoding/base32"
	"testing"
)

// TestEncodeMultiaddrStringIP4TCP pins the exact raw binary encoding of an "/ip4/.../tcp/..."
// multiaddr, computed by hand from rust-multiaddr's own `Protocol::write_bytes` (see
// multiaddr.go's doc comment): varint(4)=0x04, 4 raw octets, varint(6)=0x06, 2-byte big-endian
// port.
func TestEncodeMultiaddrStringIP4TCP(t *testing.T) {
	got, err := EncodeMultiaddrString("/ip4/1.2.3.4/tcp/18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString: %v", err)
	}

	// 18189 = 0x470D.
	want := []byte{0x04, 1, 2, 3, 4, 0x06, 0x47, 0x0d}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeMultiaddrString(/ip4/1.2.3.4/tcp/18189) = %x, want %x", got, want)
	}
}

func TestEncodeMultiaddrStringIP4TCPLowPort(t *testing.T) {
	got, err := EncodeMultiaddrString("/ip4/127.0.0.1/tcp/80")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString: %v", err)
	}
	want := []byte{0x04, 127, 0, 0, 1, 0x06, 0x00, 0x50}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeMultiaddrString(/ip4/127.0.0.1/tcp/80) = %x, want %x", got, want)
	}
}

func TestEncodeMultiaddrStringIP4TCPRejectsMalformed(t *testing.T) {
	cases := []string{
		"/ip4/1.2.3.4",
		"/ip4/1.2.3.4/tcp/",
		"/ip4/1.2.3.4/udp/18189",
		"/ip4/not-an-ip/tcp/18189",
		"/ip4/1.2.3.4/tcp/999999",
		"/ip4/::1/tcp/18189", // IPv6 given to ip4
	}
	for _, c := range cases {
		if _, err := EncodeMultiaddrString(c); err == nil {
			t.Errorf("EncodeMultiaddrString(%q): expected an error, got none", c)
		}
	}
}

// TestEncodeMultiaddrStringOnion3 pins the exact raw binary encoding of an "/onion3/..." Tor v3
// multiaddr, hand-computed from rust-multiaddr's `Protocol::write_bytes`/ONION3 (35-byte hash,
// varint(445) = [0xBD, 0x03] -- 445 = 0b1_1011_1101 -> low 7 bits 0b0111101=0x3D | 0x80 = 0xBD,
// remaining bits 0b11=0x03) and BASE32 (RFC4648, unpadded) round-tripping.
func TestEncodeMultiaddrStringOnion3(t *testing.T) {
	var hash [35]byte
	for i := range hash {
		hash[i] = byte(i)
	}
	addrStr := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])
	if len(addrStr) != 56 {
		t.Fatalf("test fixture bug: base32-encoded 35-byte hash is %d chars, want 56", len(addrStr))
	}

	got, err := EncodeMultiaddrString("/onion3/" + addrStr + ":18189")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString: %v", err)
	}

	want := make([]byte, 0, 2+35+2)
	want = append(want, 0xBD, 0x03) // varint(445)
	want = append(want, hash[:]...)
	want = append(want, 0x47, 0x0d) // 18189 big-endian

	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeMultiaddrString(/onion3/...) = %x, want %x", got, want)
	}
}

// TestEncodeMultiaddrStringOnion3AcceptsLowercase matches rust-multiaddr's own onion3 parsing,
// which uppercases the address before base32-decoding it -- so a lowercase input address string
// must decode identically to its uppercase form.
func TestEncodeMultiaddrStringOnion3AcceptsLowercase(t *testing.T) {
	var hash [35]byte
	for i := range hash {
		hash[i] = byte(255 - i)
	}
	addrStr := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])

	upper, err := EncodeMultiaddrString("/onion3/" + addrStr + ":9999")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString (uppercase): %v", err)
	}
	lower, err := EncodeMultiaddrString("/onion3/" + toLowerASCII(addrStr) + ":9999")
	if err != nil {
		t.Fatalf("EncodeMultiaddrString (lowercase): %v", err)
	}
	if !bytes.Equal(upper, lower) {
		t.Fatalf("uppercase/lowercase onion3 address encodings differ: %x vs %x", upper, lower)
	}
}

func TestEncodeMultiaddrStringOnion3RejectsMalformed(t *testing.T) {
	var hash [35]byte
	addrStr := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(hash[:])

	cases := []string{
		"/onion3/" + addrStr,               // missing port
		"/onion3/" + addrStr + ":0",        // port 0 invalid
		"/onion3/" + addrStr + ":notaport", // non-numeric port
		"/onion3/tooshort:18189",           // wrong-length base32
		"/onion3/" + addrStr + "/18189",    // wrong separator (must be ':', single segment)
	}
	for _, c := range cases {
		if _, err := EncodeMultiaddrString(c); err == nil {
			t.Errorf("EncodeMultiaddrString(%q): expected an error, got none", c)
		}
	}
}

func TestEncodeMultiaddrStringRejectsUnsupportedProtocols(t *testing.T) {
	cases := []string{
		"/ip6/::1/tcp/18189",
		"/dns4/example.com/tcp/18189",
		"not-a-multiaddr-at-all",
		"",
	}
	for _, c := range cases {
		if _, err := EncodeMultiaddrString(c); err == nil {
			t.Errorf("EncodeMultiaddrString(%q): expected an error, got none", c)
		}
	}
}

func toLowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}
