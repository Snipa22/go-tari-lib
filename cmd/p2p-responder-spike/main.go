// Command p2p-responder-spike is a throwaway spike binary (see BRIEF.md at the repo root): a
// minimal Tari P2P inbound responder that completes the Noise_XX handshake + identity exchange
// (advertising COMMUNICATION_NODE features), and serves a bounded, 1-hour-windowed get_peers
// response over `t/dht/1` for every peer it has itself seen connect or exchange identity with in
// that window. It does NOT implement full DHT store-and-forward, message propagation, or
// blocksync -- see package p2p's Serve/ResponderConfig (p2p/responder.go) for what it actually
// does, and p2p/rpc's ServeGetPeers (p2p/rpc/dht_getpeers_responder.go) for the get_peers wire
// behavior.
//
// # Advertised addresses (BRIEF2.md "Finish the advertising")
//
// A COMMUNICATION_NODE peer that advertises ZERO addresses is exactly the case a real Tari
// node's `comms/dht/src/peer_validator.rs` PeerHasNoAddresses/PeerHasNoUsableAddresses checks
// reject -- so this binary now REQUIRES at least one advertised address, via two optional CLI
// flags (at least one of which must be set, or this binary fails fast at startup rather than
// silently running unreachable):
//
//	-public-tcp-addr /ip4/<public-ip>/tcp/<port>   e.g. -public-tcp-addr /ip4/203.0.113.7/tcp/18189
//	-onion3-addr     /onion3/<addr>:<port>          e.g. -onion3-addr /onion3/abc...xyz:18189
//
// Both flags accept a full multiaddr string; each is parsed and re-encoded into the real,
// byte-exact rust-multiaddr BINARY wire format (see p2p/multiaddr.go's EncodeMultiaddrString --
// NOT a UTF-8 string -- this matters for both the outgoing PeerIdentityMsg.Addresses AND the
// IdentitySignature challenge that now covers them, see p2p/identity_signature.go) before being
// threaded into p2p.ResponderConfig.OurAddresses. Both may be set at once (e.g. a node reachable
// over both clearnet and Tor); at least one is mandatory.
package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/flynn/noise"

	"github.com/Snipa22/go-tari-lib/p2p"
	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
)

// seenPeerWindow is how long a peer we've connected to (inbound or outbound) or exchanged
// identity with stays in the get_peers list this responder serves -- see BRIEF.md point 3:
// "only peers we ourselves saw connect (in or out) or exchanged identity with in the last 1
// hour", never our entire known-peer history.
const seenPeerWindow = time.Hour

// maxServedPeers caps the number of peers ever returned from a single get_peers response,
// regardless of how many are currently in the 1-hour window -- BRIEF.md point 3: "capped in
// count", "never unbounded". rpc.ServeGetPeers ALSO enforces the requesting peer's own N bound
// server-side (see its doc comment) -- this cap is this program's own independent ceiling on top
// of that, so a get_peers request with N=0 ("give me everything") still can't make this
// responder hand out an unbounded list from its own store.
const maxServedPeers = 200

func main() {
	if err := run(); err != nil {
		log.Fatalf("p2p-responder-spike: %v", err)
	}
}

func run() error {
	var (
		addr          = flag.String("addr", ":18189", "TCP address to listen on (matches real Tari base node p2p port conventions by default)")
		keyPath       = flag.String("key", "", "path to a file holding our long-term Ristretto255 private key (32 raw bytes); if empty or the file doesn't exist, a fresh key is generated and, if -key was given, saved there for reuse across restarts")
		publicTCPAddr = flag.String("public-tcp-addr", "", "our own publicly-dialable clearnet multiaddr to advertise, e.g. /ip4/203.0.113.7/tcp/18189 (optional, but at least one of -public-tcp-addr/-onion3-addr is REQUIRED -- a COMMUNICATION_NODE peer with zero advertised addresses is rejected by real Tari nodes' peer validation)")
		onion3Addr    = flag.String("onion3-addr", "", "our own onion-v3 multiaddr to advertise, e.g. /onion3/<56-char-base32-addr>:18189 (optional, but at least one of -public-tcp-addr/-onion3-addr is REQUIRED, see -public-tcp-addr)")
	)
	flag.Parse()

	ourAddresses, err := parseAdvertisedAddresses(*publicTCPAddr, *onion3Addr)
	if err != nil {
		return err
	}

	staticKeypair, err := loadOrGenerateKeypair(*keyPath)
	if err != nil {
		return fmt.Errorf("setting up static keypair: %w", err)
	}
	log.Printf("main: our static public key: %x", staticKeypair.Public)
	log.Printf("main: advertising %d address(es): public-tcp=%q onion3=%q", len(ourAddresses), *publicTCPAddr, *onion3Addr)

	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", *addr, err)
	}
	defer listener.Close()
	log.Printf("main: listening on %s", listener.Addr())

	store := newPeerStore()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigCh
		log.Printf("main: received signal %s, shutting down", sig)
		cancel()
		listener.Close()
	}()

	cfg := p2p.ResponderConfig{
		StaticKeypair: staticKeypair,
		OurFeatures:   p2p.FeaturesCommunicationNode,
		OurAddresses:  ourAddresses,
		PeerListProvider: func() []*pb.PeerInfo {
			return store.List()
		},
		OnPeerIdentity: func(remoteAddr net.Addr, peerStaticKey []byte, identity *p2p.PeerInfo) {
			log.Printf("identity: peer=%x remote=%s features=%d user_agent=%q addresses=%v",
				peerStaticKey, remoteAddr, identity.Features, identity.UserAgent, identity.Addresses)
			store.Record(peerStaticKey, identity)
		},
		Logf: log.Printf,
	}

	err = p2p.Serve(ctx, listener, cfg)
	if err != nil && !errors.Is(err, net.ErrClosed) {
		return fmt.Errorf("serving: %w", err)
	}
	log.Printf("main: responder loop exited cleanly")
	return nil
}

// parseAdvertisedAddresses validates and encodes this binary's -public-tcp-addr/-onion3-addr
// flag values into the raw binary rust-multiaddr wire encoding p2p.ResponderConfig.OurAddresses
// expects (see p2p/multiaddr.go's EncodeMultiaddrString doc comment for exactly why that, and
// not a UTF-8 string, is required). At least one of the two flags MUST be non-empty -- fails
// fast with a clear error otherwise, rather than silently starting an unreachable
// COMMUNICATION_NODE peer (BRIEF2.md "Finish the advertising", point 1: real Tari nodes'
// comms/dht/src/peer_validator.rs PeerHasNoAddresses/PeerHasNoUsableAddresses checks reject a
// peer with zero advertised addresses).
func parseAdvertisedAddresses(publicTCPAddr, onion3Addr string) ([][]byte, error) {
	if publicTCPAddr == "" && onion3Addr == "" {
		return nil, fmt.Errorf("at least one of -public-tcp-addr or -onion3-addr must be set: a COMMUNICATION_NODE peer with no advertised addresses is rejected by real Tari nodes' peer validation and would start unreachable")
	}

	var out [][]byte
	if publicTCPAddr != "" {
		encoded, err := p2p.EncodeMultiaddrString(publicTCPAddr)
		if err != nil {
			return nil, fmt.Errorf("-public-tcp-addr %q: %w", publicTCPAddr, err)
		}
		out = append(out, encoded)
	}
	if onion3Addr != "" {
		encoded, err := p2p.EncodeMultiaddrString(onion3Addr)
		if err != nil {
			return nil, fmt.Errorf("-onion3-addr %q: %w", onion3Addr, err)
		}
		out = append(out, encoded)
	}
	return out, nil
}

// keyFileSize is the size, in bytes, of the file loadOrGenerateKeypair reads/writes: the 32-byte
// private scalar followed by the 32-byte public point, i.e. exactly noise.DHKey's two fields
// concatenated. Storing both (rather than just the private key and re-deriving the public key on
// load) avoids needing to export Ristretto255 scalar-base-multiplication from package p2p purely
// for this throwaway spike's key-persistence convenience.
const keyFileSize = 64

// loadOrGenerateKeypair loads a keypair from path (see keyFileSize) if path is non-empty and the
// file exists; otherwise it generates a fresh keypair and, if path is non-empty, saves it there
// (mode 0600) for reuse across restarts. An empty path always generates an ephemeral, unsaved
// keypair -- fine for a throwaway spike run.
func loadOrGenerateKeypair(path string) (noise.DHKey, error) {
	if path != "" {
		if raw, err := os.ReadFile(path); err == nil {
			if len(raw) != keyFileSize {
				return noise.DHKey{}, fmt.Errorf("key file %s has %d bytes, want %d", path, len(raw), keyFileSize)
			}
			return noise.DHKey{
				Private: append([]byte(nil), raw[:32]...),
				Public:  append([]byte(nil), raw[32:]...),
			}, nil
		} else if !os.IsNotExist(err) {
			return noise.DHKey{}, fmt.Errorf("reading key file %s: %w", path, err)
		}
	}

	keypair, err := p2p.GenerateRistrettoKeypair()
	if err != nil {
		return noise.DHKey{}, fmt.Errorf("generating a fresh keypair: %w", err)
	}

	if path != "" {
		raw := append(append([]byte(nil), keypair.Private...), keypair.Public...)
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			return noise.DHKey{}, fmt.Errorf("saving fresh keypair to %s: %w", path, err)
		}
	}
	return keypair, nil
}

// peerStore is the "peers we've seen connect (in or out) or exchanged identity with in the last
// hour" store BRIEF.md point 3 describes -- a simple mutex-protected map + timestamp pruning, no
// DB (this is a throwaway spike). Keyed by hex-encoded static public key so repeated
// connections/identity-exchanges from the same peer just refresh its timestamp rather than
// accumulating duplicate entries.
type peerStore struct {
	mu    sync.Mutex
	peers map[string]seenPeer
}

type seenPeer struct {
	info   *pb.PeerInfo
	seenAt time.Time
}

func newPeerStore() *peerStore {
	return &peerStore{peers: make(map[string]seenPeer)}
}

// Record records (or refreshes the timestamp of, if already present) peerStaticKey as seen
// right now, storing identity's Features/Addresses alongside it in the pb.PeerInfo/
// PeerIdentityClaim shape rpc.ServeGetPeers expects.
func (s *peerStore) Record(peerStaticKey []byte, identity *p2p.PeerInfo) {
	key := hex.EncodeToString(peerStaticKey)

	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[key] = seenPeer{
		info: &pb.PeerInfo{
			PublicKey: append([]byte(nil), peerStaticKey...),
			Claims: []*pb.PeerIdentityClaim{
				{
					Addresses:    identity.Addresses,
					PeerFeatures: identity.Features,
				},
			},
		},
		seenAt: time.Now(),
	}
}

// List returns the current, pruned (entries older than seenPeerWindow are dropped and forgotten
// -- see BRIEF.md point 3's "not our entire known-peer history" requirement), count-capped (at
// maxServedPeers) list of peers this responder should serve on the next get_peers request. The
// returned slice (and its elements) are never mutated afterwards by peerStore -- rpc.ServeGetPeers
// itself also never mutates what it's handed (see boundPeerClaims/boundClaimAddresses in
// p2p/rpc/dht_getpeers_responder.go) -- so sharing these *pb.PeerInfo pointers directly (rather
// than deep-copying per call) is safe.
func (s *peerStore) List() []*pb.PeerInfo {
	now := time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	for key, p := range s.peers {
		if now.Sub(p.seenAt) > seenPeerWindow {
			delete(s.peers, key)
		}
	}

	out := make([]*pb.PeerInfo, 0, len(s.peers))
	for _, p := range s.peers {
		out = append(out, p.info)
		if len(out) >= maxServedPeers {
			break
		}
	}
	return out
}
