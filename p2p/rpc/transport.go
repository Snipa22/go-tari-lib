package rpc

// Transport is the minimal session interface this package needs from an already
// Noise_XX-handshaked connection: sending and receiving single application-layer frames.
//
// p2p's exported *p2p.Session type (see p2p/session.go) satisfies this interface via its
// existing SendFrame/ReceiveFrame methods -- this interface exists purely so that p2p/rpc does
// not need to import package p2p directly. Importing p2p from here would create an import
// cycle: p2p's own p2p/chainmetadata_probe.go (the top-level ProbeChainMetadata convenience,
// p2p/RPC_TOR_SPEC.md section A4) needs to call into p2p/rpc's GetChainMetadata, so the
// dependency has to run p2p -> p2p/rpc, not the other way around.
type Transport interface {
	// SendFrame encrypts plaintext as a single Noise transport message and writes it to the
	// wire (see (*p2p.Session).SendFrame).
	SendFrame(plaintext []byte) error
	// ReceiveFrame reads and decrypts a single Noise transport message from the wire (see
	// (*p2p.Session).ReceiveFrame).
	ReceiveFrame() ([]byte, error)
}
