package p2p

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/flynn/noise"
	"github.com/hashicorp/yamux"

	pb "github.com/Snipa22/go-tari-lib/p2p/proto"
	rpcpkg "github.com/Snipa22/go-tari-lib/p2p/rpc"
)

// responderHandshakeTimeout is the default bound on ResponderHandshake+ExchangeIdentityWithOptions
// for a single accepted connection, applied via conn.SetDeadline (NOT ctx alone -- the underlying
// reads in ResponderHandshake/ExchangeIdentity are blocking net.Conn I/O that only ctx-cancels at
// call boundaries, not mid-read; see handshake.go's checkContext and session.go's
// ExchangeIdentityWithOptions doc comments), matching the existing 10-second identity-exchange
// timeout pattern (identityExchangeTimeout in identity.go). Used when ResponderConfig.
// ConnectionTimeout is zero.
const responderHandshakeTimeout = identityExchangeTimeout

// ResponderConfig configures Serve (this file's minimal Listen/Accept responder loop). See
// Serve's doc comment for the full per-connection lifecycle this drives.
type ResponderConfig struct {
	// StaticKeypair is our own long-term Ristretto255 identity keypair, used for every accepted
	// connection's Noise_XX handshake and identity-signature.
	StaticKeypair noise.DHKey

	// OurFeatures is advertised in our outgoing PeerIdentityMsg.Features on every accepted
	// connection (see IdentityOptions.Features/FeaturesCommunicationNode in identity.go). The
	// zero value (0, COMMUNICATION_CLIENT) is a legal but almost certainly wrong choice for a
	// responder that wants real Tari nodes to actually pool/gossip it -- see
	// FeaturesCommunicationNode's doc comment.
	OurFeatures uint32

	// OurAddresses is advertised in our outgoing PeerIdentityMsg.Addresses on every accepted
	// connection. nil/empty is a legal choice (an unreachable-by-others-from-this-message-alone
	// peer, fine for this spike).
	OurAddresses [][]byte

	// PeerListProvider is called once per get_peers request received on any substream, and must
	// return the current bounded, time-windowed "peers we've seen recently" list to serve. Serve
	// itself knows nothing about time windows or storage -- that's entirely this callback's
	// job. May be nil, in which case every get_peers request is served an empty list.
	//
	// ctx is the same context.Context passed to Serve (cancelled on shutdown, NOT per-call
	// bounded -- callers backed by a real, possibly slow/unreliable store (e.g. a Postgres
	// query) that want a per-call deadline should derive their own context.WithTimeout from ctx
	// inside the callback). A non-nil error is treated as "no peers available right now": it is
	// logged via cfg.Logf and the get_peers request is served an EMPTY list rather than
	// crashing or hanging the substream/connection -- a transient store failure must never take
	// down an otherwise-healthy inbound connection.
	PeerListProvider func(ctx context.Context) ([]*pb.PeerInfo, error)

	// OnPeerIdentity, if non-nil, is called after a successful Noise_XX handshake + identity
	// exchange on an accepted connection, reporting the peer's recovered static public key and
	// full decoded identity. Intended for the caller to record "peers we've seen connect or
	// exchange identity with" (see cmd/p2p-responder-spike/main.go) and/or log it.
	OnPeerIdentity func(remoteAddr net.Addr, peerStaticKey []byte, identity *PeerInfo)

	// Logf, if non-nil, is called with printf-style verbose tracing of every inbound connection
	// attempt, handshake result, identity exchange result, and negotiated/rejected substream
	// protocol -- see Serve's doc comment. A nil Logf means no logging (the default); callers
	// that want stdout tracing (e.g. cmd/p2p-responder-spike/main.go) should pass something like
	// log.Printf.
	Logf func(format string, args ...interface{})

	// ConnectionTimeout bounds ResponderHandshake+ExchangeIdentityWithOptions for a single
	// accepted connection (see responderHandshakeTimeout's doc comment for why this needs to be
	// a conn.SetDeadline-based bound, not just a context). Zero means
	// responderHandshakeTimeout (10s, matching the existing identity-exchange timeout pattern).
	// This deadline is CLEARED once identity exchange succeeds -- it does not bound the
	// connection's subsequent long-lived Yamux/RPC lifetime.
	ConnectionTimeout time.Duration

	// The callbacks below exist purely for observability (e.g. a caller wiring up Prometheus
	// counters, see go-tari-netmap's cmd/netmap-p2p-responder) -- every event they report
	// already produces an equivalent cfg.Logf line at the same call site; these callbacks just
	// give a structured, machine-countable hook onto the SAME events, rather than requiring a
	// caller to parse log lines. All are optional (nil-safe, no-op if unset) and are called
	// synchronously, inline, from the same per-connection/per-substream goroutine that would
	// otherwise just call cfg.logf -- like OnPeerIdentity, they must not block or panic, since a
	// slow/panicking callback would hang or crash that connection's goroutine.

	// OnConnectionAccepted, if non-nil, is called once per accepted inbound TCP connection,
	// immediately after listener.Accept() succeeds and before any handshake attempt.
	OnConnectionAccepted func(remoteAddr net.Addr)

	// OnHandshakeResult, if non-nil, is called once per accepted connection with the outcome of
	// ResponderHandshake (Noise_XX). success is true iff the handshake completed without error.
	OnHandshakeResult func(remoteAddr net.Addr, success bool)

	// OnIdentityExchangeResult, if non-nil, is called once per connection that completed a
	// successful handshake, with the outcome of ExchangeIdentityWithOptions. success is true
	// iff the identity exchange completed without error. Unlike OnPeerIdentity (which only
	// fires on success), this fires on BOTH outcomes, so a caller can count failures too.
	OnIdentityExchangeResult func(remoteAddr net.Addr, success bool)

	// OnGetPeersServed, if non-nil, is called once per substream on which a get_peers request
	// was successfully served (i.e. rpcpkg.ServeGetPeers returned nil), with the number of
	// peers included in that response (which may be 0).
	OnGetPeersServed func(remoteAddr net.Addr, peerCount int)

	// OnSubstreamProtocolDeclined, if non-nil, is called once per substream on which the peer
	// requested a protocol id other than the one(s) this responder supports (currently always
	// just `t/dht/1`, see handleResponderSubstream) -- i.e. NOT_SUPPORTED was sent back on the
	// wire. protocol is the REQUESTED protocol id exactly as the peer sent it (e.g.
	// "t/msg/0.1", "t/blksync/1"), recovered via rpcpkg.UnsupportedProtocolError -- see that
	// type's doc comment for why a plain sentinel error can't carry this.
	OnSubstreamProtocolDeclined func(remoteAddr net.Addr, protocol []byte)
}

func (c ResponderConfig) onConnectionAccepted(remoteAddr net.Addr) {
	if c.OnConnectionAccepted != nil {
		c.OnConnectionAccepted(remoteAddr)
	}
}

func (c ResponderConfig) onHandshakeResult(remoteAddr net.Addr, success bool) {
	if c.OnHandshakeResult != nil {
		c.OnHandshakeResult(remoteAddr, success)
	}
}

func (c ResponderConfig) onIdentityExchangeResult(remoteAddr net.Addr, success bool) {
	if c.OnIdentityExchangeResult != nil {
		c.OnIdentityExchangeResult(remoteAddr, success)
	}
}

func (c ResponderConfig) onGetPeersServed(remoteAddr net.Addr, peerCount int) {
	if c.OnGetPeersServed != nil {
		c.OnGetPeersServed(remoteAddr, peerCount)
	}
}

func (c ResponderConfig) onSubstreamProtocolDeclined(remoteAddr net.Addr, protocol []byte) {
	if c.OnSubstreamProtocolDeclined != nil {
		c.OnSubstreamProtocolDeclined(remoteAddr, protocol)
	}
}

func (c ResponderConfig) logf(format string, args ...interface{}) {
	if c.Logf != nil {
		c.Logf(format, args...)
	}
}

func (c ResponderConfig) connectionTimeout() time.Duration {
	if c.ConnectionTimeout > 0 {
		return c.ConnectionTimeout
	}
	return responderHandshakeTimeout
}

// knownPeers calls c.PeerListProvider (if set) and returns its peer list. A nil PeerListProvider,
// or one that returns a non-nil error, yields an empty (nil) list -- see PeerListProvider's doc
// comment on why a store failure must degrade to "no peers" rather than propagate and take down
// the substream/connection. Errors are logged via c.logf, tagged with remote for traceability.
func (c ResponderConfig) knownPeers(ctx context.Context, remote net.Addr) []*pb.PeerInfo {
	if c.PeerListProvider == nil {
		return nil
	}
	peers, err := c.PeerListProvider(ctx)
	if err != nil {
		c.logf("p2p: %s: PeerListProvider failed, serving an empty peer list: %v", remote, err)
		return nil
	}
	return peers
}

// Serve runs a minimal inbound P2P responder loop on listener until ctx is cancelled or
// listener.Accept() returns an error (whichever happens first): for each accepted net.Conn, in
// its own goroutine:
//
//  1. ResponderHandshake (Noise_XX, this package's existing responder implementation) then
//     ExchangeIdentityWithOptions (advertising cfg.OurFeatures/cfg.OurAddresses -- e.g.
//     FeaturesCommunicationNode, so real Tari DHT connectivity pools actually gossip this peer;
//     see identity.go), both bounded by cfg.ConnectionTimeout (default 10s) via conn.SetDeadline
//     -- cleared afterwards so it doesn't cut off the long-lived connection below.
//  2. cfg.OnPeerIdentity is called with the peer's recovered static key + decoded identity.
//  3. The Session is upgraded to a Yamux SERVER (yamux.Server, mirroring
//     ProbeGetPeersWithOptions's client-side yamux.Client/.Open() -- see getpeers_probe.go),
//     and its Accept() is looped for inbound substreams (each in its own goroutine).
//  4. Each substream is wrapped as a Transport (rpcpkg.NewStreamTransport) and handed to
//     rpcpkg.ServeGetPeers, which itself negotiates ONLY `t/dht/1` -- any other requested
//     protocol (`t/tari/messaging/*`, `t/blksync/1`, etc.) gets NOT_SUPPORTED on the wire and
//     ServeGetPeers returns an error; either way, only THAT substream is closed afterwards, never
//     the whole connection. No message-propagation, DHT store-and-forward, or blocksync is (or
//     ever will be) implemented here -- see BRIEF.md's explicit scope boundary.
//
// A connection whose handshake or identity exchange fails is logged (via cfg.Logf) and closed;
// it does not stop the Accept loop for subsequent connections. Serve returns the error that
// stopped the Accept loop (nil if ctx was cancelled and that's why Accept unblocked --
// listener.Close() is the caller's responsibility either way, typically via context cancellation
// closing it, e.g. by calling listener.Close() from a goroutine watching ctx.Done()).
//
// Serve does not return until every connection/substream goroutine it spawned has fully
// finished (tracked via an internal sync.WaitGroup) -- this matters primarily for callers (e.g.
// this package's own tests) that need a hard guarantee no more logging/callback activity will
// happen once Serve returns, rather than a real production concern for the standalone spike
// binary (which just runs Serve until the process exits).
func Serve(ctx context.Context, listener net.Listener, cfg ResponderConfig) error {
	var wg sync.WaitGroup
	defer wg.Wait()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return fmt.Errorf("p2p: accepting inbound connection: %w", err)
			}
		}
		cfg.logf("p2p: accepted inbound connection from %s", conn.RemoteAddr())
		cfg.onConnectionAccepted(conn.RemoteAddr())
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleResponderConn(ctx, conn, cfg, &wg)
		}()
	}
}

// handleResponderConn runs the full per-connection lifecycle described in Serve's doc comment
// for a single accepted conn. wg is the SAME WaitGroup Serve waits on before returning --
// handleResponderConn registers each substream goroutine it spawns on it too, so Serve's final
// wg.Wait() blocks until every substream handler (not just the top-level connection goroutine)
// has finished as well.
func handleResponderConn(ctx context.Context, conn net.Conn, cfg ResponderConfig, wg *sync.WaitGroup) {
	defer conn.Close()

	remote := conn.RemoteAddr()

	if err := conn.SetDeadline(time.Now().Add(cfg.connectionTimeout())); err != nil {
		cfg.logf("p2p: %s: setting handshake deadline: %v", remote, err)
		return
	}

	session, err := ResponderHandshake(ctx, conn, cfg.StaticKeypair)
	if err != nil {
		cfg.logf("p2p: %s: Noise_XX handshake failed: %v", remote, err)
		cfg.onHandshakeResult(remote, false)
		return
	}
	cfg.logf("p2p: %s: Noise_XX handshake succeeded, peer static key=%x", remote, session.PeerStaticKey)
	cfg.onHandshakeResult(remote, true)

	identity, err := session.ExchangeIdentityWithOptions(ctx, IdentityOptions{
		Features:  cfg.OurFeatures,
		Addresses: cfg.OurAddresses,
	})
	if err != nil {
		cfg.logf("p2p: %s: identity exchange failed: %v", remote, err)
		cfg.onIdentityExchangeResult(remote, false)
		return
	}
	cfg.logf("p2p: %s: identity exchange succeeded: features=%d user_agent=%q addresses=%v",
		remote, identity.Features, identity.UserAgent, identity.Addresses)
	cfg.onIdentityExchangeResult(remote, true)

	if cfg.OnPeerIdentity != nil {
		cfg.OnPeerIdentity(remote, session.PeerStaticKey, identity)
	}

	// The handshake+identity-exchange deadline above must not cut off the long-lived Yamux/RPC
	// traffic that follows -- clear it now that the bounded phase is done.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		cfg.logf("p2p: %s: clearing post-handshake deadline: %v", remote, err)
		return
	}

	adapter := newSessionReadWriteCloser(session)
	yamuxSession, err := yamux.Server(adapter, nil)
	if err != nil {
		cfg.logf("p2p: %s: establishing Yamux server session: %v", remote, err)
		return
	}
	defer yamuxSession.Close()

	for {
		stream, err := yamuxSession.Accept()
		if err != nil {
			cfg.logf("p2p: %s: Yamux session ended: %v", remote, err)
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleResponderSubstream(ctx, remote, stream, cfg)
		}()
	}
}

// handleResponderSubstream serves exactly one inbound Yamux substream: negotiate `t/dht/1` (the
// only protocol this responder supports) and, if negotiated, serve get_peers via
// rpcpkg.ServeGetPeers, which internally handles both the negotiation and (if negotiated) the
// full get_peers RPC lifecycle -- see rpcpkg.ServeGetPeers's doc comment. Any other requested
// protocol is NOT_SUPPORTED on the wire by that same call; either way, only this substream is
// closed afterwards.
//
// ctx is passed through to cfg.PeerListProvider (see its doc comment) -- it is the connection's
// ctx (ultimately Serve's ctx), not a per-substream-scoped one.
func handleResponderSubstream(ctx context.Context, remote net.Addr, stream yamuxStream, cfg ResponderConfig) {
	defer stream.Close()

	transport := rpcpkg.NewStreamTransport(stream)
	peers := cfg.knownPeers(ctx, remote)

	if err := rpcpkg.ServeGetPeers(transport, peers); err != nil {
		cfg.logf("p2p: %s: substream: %v", remote, err)
		var unsupported *rpcpkg.UnsupportedProtocolError
		if errors.As(err, &unsupported) {
			cfg.onSubstreamProtocolDeclined(remote, unsupported.Requested)
		}
		return
	}
	cfg.logf("p2p: %s: substream: served get_peers with %d peer(s)", remote, len(peers))
	cfg.onGetPeersServed(remote, len(peers))
}

// yamuxStream is the minimal interface handleResponderSubstream needs from a Yamux substream
// (*yamux.Stream satisfies this via its embedded net.Conn) -- named here purely for readability,
// not because any Yamux-specific behavior is used beyond plain io.ReadWriteCloser semantics
// (rpcpkg.NewStreamTransport only requires io.ReadWriteCloser).
type yamuxStream interface {
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
	Close() error
}
