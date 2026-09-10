package p2p

import (
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// This file implements just enough of the real `multiaddr` crate's BINARY wire encoding
// (source: github.com/multiformats/rust-multiaddr, `multiaddr = "0.18.2"` -- the exact version
// tari/comms/core/Cargo.toml depends on) to build/parse the two multiaddr forms this repo's
// responder needs to advertise: `/ip4/<ipv4>/tcp/<port>` and `/onion3/<base32-addr>:<port>`.
//
// IMPORTANT, independently confirmed from source (do not assume otherwise): every place real
// Tari code puts a Multiaddr on the wire in a PeerIdentityMsg/IdentitySignature challenge uses
// Multiaddr's raw BINARY encoding, NOT its human-readable string form --
//
//   - tari/comms/core/src/protocol/identity.rs, `identity_exchange`:
//     `addresses: node_identity.public_addresses().iter().map(|a| a.to_vec()).collect()` --
//     `Multiaddr::to_vec` (rust-multiaddr src/lib.rs) is `Vec::from(&self.bytes[..])`, the raw
//     binary encoding.
//   - tari/comms/core/src/peer_manager/identity_signature.rs, `construct_challenge`:
//     `addresses.into_iter().fold(challenge, |challenge, addr| challenge.chain(addr))` where
//     `addr: &Multiaddr` and `chain` takes `impl AsRef<[u8]>` -- `Multiaddr`'s `AsRef<[u8]>` impl
//     (rust-multiaddr src/lib.rs) also returns the same raw binary encoding.
//   - tari/comms/core/src/connection_manager/common.rs, `validate_peer_identity_message`:
//     `addresses.into_iter().map(Multiaddr::try_from)` -- `TryFrom<Vec<u8>>` for Multiaddr
//     (rust-multiaddr src/lib.rs) parses that same raw binary encoding back.
//
// So `PeerIdentityMsg.Addresses` / `IdentityOptions.Addresses` / `ResponderConfig.OurAddresses`
// in this package must carry that raw binary encoding, NOT a UTF-8 multiaddr string -- this is
// the "confirm, don't assume" byte-format BRIEF2.md called out, and it resolves the other way
// from BRIEF2.md's own tentative guess.
//
// Binary format (rust-multiaddr src/protocol.rs, `Protocol::write_bytes`/`from_bytes`): a
// concatenation of components, each `unsigned_varint::encode::u32(protocol_code) ++ payload`,
// where `unsigned_varint`'s encoding is plain LEB128 -- byte-identical to Go's
// `encoding/binary.AppendUvarint`/`Uvarint` (top bit = continuation, 7 payload bits per byte,
// least-significant group first). Protocol codes and payload shapes (from the multiaddr
// protocol table, `multiaddr/protocols.csv`, as hardcoded consts in rust-multiaddr's
// protocol.rs):
//
//	ip4    = 4   : payload = 4 raw octets, network byte order (Ipv4Addr::octets())
//	tcp    = 6   : payload = 2-byte big-endian port
//	onion3 = 445 : payload = 35-byte Tor v3 service-id hash ++ 2-byte big-endian port
const (
	multiaddrProtoIP4    = 4
	multiaddrProtoTCP    = 6
	multiaddrProtoOnion3 = 445
)

// onion3HashLen is the fixed length, in bytes, of the Tor v3 "hash" component of an
// `/onion3/...` multiaddr (32-byte ed25519 public key + 2-byte checksum + 1-byte version,
// rust-multiaddr's `read_onion3_impl!(read_onion3, 35, 56)` -- the "35" -- and Onion3Addr::hash).
const onion3HashLen = 35

// onion3EncodedLen is the fixed length, in base32 characters, of that same 35-byte hash when
// base32-encoded without padding (35*8 bits / 5 bits-per-base32-char = 56 exactly, hence no
// padding is ever needed -- matching rust-multiaddr's `read_onion3_impl!(..., 56)`).
const onion3EncodedLen = 56

// onion3Base32 is RFC4648 base32 (unpadded), matching `data_encoding::BASE32` as used by
// rust-multiaddr's `read_onion3`/onion3 Display impl (both upper- and lower-case on the wire
// decode to the same bytes -- rust-multiaddr itself calls `.to_uppercase()` before decoding, so
// this parser does the same for case-insensitive acceptance).
var onion3Base32 = base32.StdEncoding.WithPadding(base32.NoPadding)

// EncodeMultiaddrString parses s (a UTF-8 multiaddr string, e.g. "/ip4/1.2.3.4/tcp/18189" or
// "/onion3/<56-char-base32-addr>:18189") and returns its real, byte-exact rust-multiaddr BINARY
// wire encoding (see this file's doc comment) -- the exact byte slice a real Tari node expects
// in PeerIdentityMsg.Addresses and chains into the identity signature challenge.
//
// Only the two multiaddr forms this repo's responder actually needs to advertise are supported
// (see ResponderConfig.OurAddresses / cmd/p2p-responder-spike/main.go's CLI flags); anything else
// returns a clear error rather than silently guessing at an encoding.
func EncodeMultiaddrString(s string) ([]byte, error) {
	switch {
	case strings.HasPrefix(s, "/ip4/"):
		return encodeIP4TCPMultiaddrString(s)
	case strings.HasPrefix(s, "/onion3/"):
		return encodeOnion3MultiaddrString(s)
	default:
		return nil, fmt.Errorf("p2p: unsupported multiaddr %q: this package's minimal encoder only supports /ip4/<ipv4>/tcp/<port> and /onion3/<addr>:<port> forms", s)
	}
}

// encodeIP4TCPMultiaddrString parses exactly "/ip4/<ipv4>/tcp/<port>" (no more, no fewer path
// segments -- a real Tari address always has both components together, and this repo only ever
// needs to build addresses in that combined shape).
func encodeIP4TCPMultiaddrString(s string) ([]byte, error) {
	parts := strings.Split(s, "/")
	if len(parts) != 5 || parts[0] != "" || parts[1] != "ip4" || parts[3] != "tcp" {
		return nil, fmt.Errorf("p2p: malformed multiaddr %q: want exactly /ip4/<ipv4>/tcp/<port>", s)
	}

	ip := net.ParseIP(parts[2])
	if ip == nil {
		return nil, fmt.Errorf("p2p: malformed multiaddr %q: %q is not a valid IP address", s, parts[2])
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, fmt.Errorf("p2p: malformed multiaddr %q: %q is not a valid IPv4 address", s, parts[2])
	}

	port, err := strconv.ParseUint(parts[4], 10, 16)
	if err != nil {
		return nil, fmt.Errorf("p2p: malformed multiaddr %q: invalid TCP port %q: %w", s, parts[4], err)
	}

	return encodeIP4TCPMultiaddr(ip4, uint16(port)), nil
}

// encodeIP4TCPMultiaddr builds the raw binary encoding of an `/ip4/<ip4>/tcp/<port>` multiaddr
// component pair (see this file's doc comment for the exact byte layout). ip4 must be a 4-byte
// (net.IP.To4()-shaped) slice.
func encodeIP4TCPMultiaddr(ip4 net.IP, port uint16) []byte {
	buf := make([]byte, 0, 1+4+1+2)
	buf = binary.AppendUvarint(buf, multiaddrProtoIP4)
	buf = append(buf, ip4[:4]...)
	buf = binary.AppendUvarint(buf, multiaddrProtoTCP)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	buf = append(buf, portBuf[:]...)
	return buf
}

// encodeOnion3MultiaddrString parses exactly "/onion3/<addr>:<port>" where <addr> is a
// 56-character base32 encoding of the 35-byte Tor v3 service-id hash (matching rust-multiaddr's
// `read_onion3`/Onion3Addr -- see this file's doc comment). Per rust-multiaddr's own onion3
// parsing (`read_onion_impl!`), port 0 is rejected as invalid.
func encodeOnion3MultiaddrString(s string) ([]byte, error) {
	rest := strings.TrimPrefix(s, "/onion3/")
	if strings.Contains(rest, "/") {
		return nil, fmt.Errorf("p2p: malformed multiaddr %q: want exactly /onion3/<addr>:<port> (a single path segment after /onion3/)", s)
	}

	idx := strings.LastIndex(rest, ":")
	if idx < 0 {
		return nil, fmt.Errorf("p2p: malformed multiaddr %q: want /onion3/<addr>:<port>, missing ':'", s)
	}
	addrPart, portPart := rest[:idx], rest[idx+1:]

	if len(addrPart) != onion3EncodedLen {
		return nil, fmt.Errorf("p2p: malformed multiaddr %q: onion3 address %q must be exactly %d base32 characters, got %d", s, addrPart, onion3EncodedLen, len(addrPart))
	}
	decoded, err := onion3Base32.DecodeString(strings.ToUpper(addrPart))
	if err != nil {
		return nil, fmt.Errorf("p2p: malformed multiaddr %q: invalid base32 onion3 address %q: %w", s, addrPart, err)
	}
	if len(decoded) != onion3HashLen {
		return nil, fmt.Errorf("p2p: malformed multiaddr %q: decoded onion3 address is %d bytes, want %d", s, len(decoded), onion3HashLen)
	}

	port, err := strconv.ParseUint(portPart, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("p2p: malformed multiaddr %q: invalid port %q: %w", s, portPart, err)
	}
	if port == 0 {
		return nil, fmt.Errorf("p2p: malformed multiaddr %q: port 0 is not valid for an onion3 address", s)
	}

	var hash [onion3HashLen]byte
	copy(hash[:], decoded)
	return encodeOnion3Multiaddr(hash, uint16(port)), nil
}

// encodeOnion3Multiaddr builds the raw binary encoding of an `/onion3/<hash>:<port>` multiaddr
// component (see this file's doc comment for the exact byte layout).
func encodeOnion3Multiaddr(hash [onion3HashLen]byte, port uint16) []byte {
	buf := make([]byte, 0, 2+onion3HashLen+2)
	buf = binary.AppendUvarint(buf, multiaddrProtoOnion3)
	buf = append(buf, hash[:]...)
	var portBuf [2]byte
	binary.BigEndian.PutUint16(portBuf[:], port)
	buf = append(buf, portBuf[:]...)
	return buf
}
