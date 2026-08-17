package nodeGRPC

import (
	"context"
	"net"
	"sync"
	"testing"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"
)

// TestNewClient_ReturnsUsableClient verifies that NewClient returns a non-nil *Client and no
// error for a syntactically valid address. This does not require a live Tari gRPC endpoint:
// grpc.NewClient performs no I/O when constructing the channel (per its doc comment, "No I/O is
// performed. Use of the ClientConn for RPCs will automatically cause it to connect."), so this
// test only exercises the lazy/non-blocking construction path, not a live connection.
func TestNewClient_ReturnsUsableClient(t *testing.T) {
	c, err := NewClient("127.0.0.1:18142")
	if err != nil {
		t.Fatalf("NewClient returned unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("NewClient returned a nil *Client")
	}
	if c.conn == nil {
		t.Fatal("NewClient returned a *Client with a nil underlying connection")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close returned unexpected error: %v", err)
	}
}

// TestNewClient_IndependentConnections proves the actual point of this change: two Clients
// created for two different (or even the same) node addresses hold genuinely separate
// *grpc.ClientConn values, not a shared/global singleton. This is what makes it safe to use
// many Clients concurrently against many nodes.
func TestNewClient_IndependentConnections(t *testing.T) {
	c1, err := NewClient("127.0.0.1:18142")
	if err != nil {
		t.Fatalf("NewClient(c1) returned unexpected error: %v", err)
	}
	defer c1.Close()

	c2, err := NewClient("127.0.0.1:18143")
	if err != nil {
		t.Fatalf("NewClient(c2) returned unexpected error: %v", err)
	}
	defer c2.Close()

	if c1 == c2 {
		t.Fatal("expected two distinct *Client values, got the same pointer")
	}
	if c1.conn == c2.conn {
		t.Fatal("expected two distinct underlying *grpc.ClientConn values, got the same connection — this is exactly the shared-state bug being fixed")
	}
}

// TestNewClient_ConcurrentCreation constructs several Clients concurrently against distinct
// addresses and confirms there is no data race and every Client ends up with its own conn.
// Run with `go test -race` to exercise the race detector.
func TestNewClient_ConcurrentCreation(t *testing.T) {
	addrs := []string{
		"127.0.0.1:18142",
		"127.0.0.1:18143",
		"127.0.0.1:18144",
		"127.0.0.1:18145",
		"127.0.0.1:18146",
	}

	clients := make([]*Client, len(addrs))
	var wg sync.WaitGroup
	for i, addr := range addrs {
		wg.Add(1)
		go func(idx int, address string) {
			defer wg.Done()
			c, err := NewClient(address)
			if err != nil {
				t.Errorf("NewClient(%q) returned unexpected error: %v", address, err)
				return
			}
			clients[idx] = c
		}(i, addr)
	}
	wg.Wait()

	seen := make(map[*Client]struct{}, len(clients))
	for i, c := range clients {
		if c == nil {
			t.Fatalf("clients[%d] is nil", i)
		}
		if _, ok := seen[c]; ok {
			t.Fatalf("clients[%d] duplicates a previously seen *Client pointer", i)
		}
		seen[c] = struct{}{}
		if err := c.Close(); err != nil {
			t.Errorf("Close on clients[%d] returned unexpected error: %v", i, err)
		}
	}
}

// TestDeprecatedPackageLevelAPI_StillWorks confirms the old package-level singleton API keeps
// functioning exactly as before, for backward compatibility with existing consumers.
func TestDeprecatedPackageLevelAPI_StillWorks(t *testing.T) {
	InitNodeGRPC("127.0.0.1:18142")
	if grpcConn == nil {
		t.Fatal("InitNodeGRPC did not populate the package-level grpcConn")
	}
}

// fakeBaseNodeServer implements just enough of tari_generated.BaseNodeServer to exercise
// GetSyncProgress and GetMempoolStats over an in-memory bufconn listener.
type fakeBaseNodeServer struct {
	tari_generated.UnimplementedBaseNodeServer
}

func (f *fakeBaseNodeServer) GetSyncProgress(ctx context.Context, in *tari_generated.Empty) (*tari_generated.SyncProgressResponse, error) {
	return &tari_generated.SyncProgressResponse{
		TipHeight:             1000,
		LocalHeight:           998,
		State:                 tari_generated.SyncState_HEADER,
		ShortDesc:             "syncing headers",
		InitialConnectedPeers: 5,
	}, nil
}

func (f *fakeBaseNodeServer) GetMempoolStats(ctx context.Context, in *tari_generated.Empty) (*tari_generated.MempoolStatsResponse, error) {
	return &tari_generated.MempoolStatsResponse{
		UnconfirmedTxs:    12,
		ReorgTxs:          1,
		UnconfirmedWeight: 3456,
	}, nil
}

// startFakeNode spins up an in-memory GRPC server backed by bufconn, points the package-level
// grpcConn at it, and returns a cleanup func. Restores grpcConn to its prior value on cleanup so
// tests don't leak state into each other or into non-test package use.
func startFakeNode(t *testing.T) {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	tari_generated.RegisterBaseNodeServer(srv, &fakeBaseNodeServer{})

	go func() {
		_ = srv.Serve(lis)
	}()

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial bufconn: %v", err)
	}

	prevConn := grpcConn
	grpcConn = conn

	t.Cleanup(func() {
		_ = conn.Close()
		srv.Stop()
		_ = lis.Close()
		grpcConn = prevConn
	})
}

func TestGetSyncProgress(t *testing.T) {
	startFakeNode(t)

	resp, err := GetSyncProgress()
	if err != nil {
		t.Fatalf("GetSyncProgress returned error: %v", err)
	}
	if resp.GetTipHeight() != 1000 {
		t.Errorf("TipHeight = %d, want 1000", resp.GetTipHeight())
	}
	if resp.GetLocalHeight() != 998 {
		t.Errorf("LocalHeight = %d, want 998", resp.GetLocalHeight())
	}
	if resp.GetState() != tari_generated.SyncState_HEADER {
		t.Errorf("State = %v, want HEADER", resp.GetState())
	}
	if resp.GetShortDesc() != "syncing headers" {
		t.Errorf("ShortDesc = %q, want %q", resp.GetShortDesc(), "syncing headers")
	}
	if resp.GetInitialConnectedPeers() != 5 {
		t.Errorf("InitialConnectedPeers = %d, want 5", resp.GetInitialConnectedPeers())
	}
}

func TestGetMempoolStats(t *testing.T) {
	startFakeNode(t)

	resp, err := GetMempoolStats()
	if err != nil {
		t.Fatalf("GetMempoolStats returned error: %v", err)
	}
	if resp.GetUnconfirmedTxs() != 12 {
		t.Errorf("UnconfirmedTxs = %d, want 12", resp.GetUnconfirmedTxs())
	}
	if resp.GetReorgTxs() != 1 {
		t.Errorf("ReorgTxs = %d, want 1", resp.GetReorgTxs())
	}
	if resp.GetUnconfirmedWeight() != 3456 {
		t.Errorf("UnconfirmedWeight = %d, want 3456", resp.GetUnconfirmedWeight())
	}
}

// TestClient_GetSyncProgressAndGetMempoolStats verifies the per-connection Client methods for
// the two RPCs added by this PR behave the same as their deprecated package-level counterparts,
// added during rebase-conflict resolution against feat/nodegrpc-client-type (merged first).
func TestClient_GetSyncProgressAndGetMempoolStats(t *testing.T) {
	lis := bufconn.Listen(1024 * 1024)
	srv := grpc.NewServer()
	tari_generated.RegisterBaseNodeServer(srv, &fakeBaseNodeServer{})
	go func() {
		_ = srv.Serve(lis)
	}()
	t.Cleanup(func() {
		srv.Stop()
		_ = lis.Close()
	})

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to dial bufconn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	c := &Client{conn: conn}

	syncResp, err := c.GetSyncProgress()
	if err != nil {
		t.Fatalf("Client.GetSyncProgress returned error: %v", err)
	}
	if syncResp.GetTipHeight() != 1000 {
		t.Errorf("TipHeight = %d, want 1000", syncResp.GetTipHeight())
	}

	mempoolResp, err := c.GetMempoolStats()
	if err != nil {
		t.Fatalf("Client.GetMempoolStats returned error: %v", err)
	}
	if mempoolResp.GetUnconfirmedTxs() != 12 {
		t.Errorf("UnconfirmedTxs = %d, want 12", mempoolResp.GetUnconfirmedTxs())
	}
}
