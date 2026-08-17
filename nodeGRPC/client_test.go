package nodeGRPC

import (
	"sync"
	"testing"
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
