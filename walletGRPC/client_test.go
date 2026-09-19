package walletGRPC

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// TestNew_ReturnsUsableClient verifies that New returns a non-nil *Client and no error for a
// syntactically valid address. This does not require a live Tari wallet gRPC endpoint:
// grpc.NewClient performs no I/O when constructing the channel (per its doc comment, "No I/O is
// performed. Use of the ClientConn for RPCs will automatically cause it to connect."), so this
// test only exercises the lazy/non-blocking construction path, not a live connection.
func TestNew_ReturnsUsableClient(t *testing.T) {
	c, err := New("127.0.0.1:18143")
	if err != nil {
		t.Fatalf("New returned unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("New returned a nil *Client")
	}
	if c.conn == nil {
		t.Fatal("New returned a *Client with a nil underlying connection")
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close returned unexpected error: %v", err)
	}
}

// TestNew_IndependentConnections proves the actual point of this change: two Clients created
// for two different addresses hold genuinely separate *grpc.ClientConn values, not a
// shared/global singleton. This is what makes it safe to use many Clients concurrently against
// many wallets.
func TestNew_IndependentConnections(t *testing.T) {
	c1, err := New("127.0.0.1:18143")
	if err != nil {
		t.Fatalf("New(c1) returned unexpected error: %v", err)
	}
	defer c1.Close()

	c2, err := New("127.0.0.1:18144")
	if err != nil {
		t.Fatalf("New(c2) returned unexpected error: %v", err)
	}
	defer c2.Close()

	if c1 == c2 {
		t.Fatal("expected two distinct *Client values, got the same pointer")
	}
	if c1.conn == c2.conn {
		t.Fatal("expected two distinct underlying *grpc.ClientConn values, got the same connection — this is exactly the shared-state bug being fixed")
	}
}

// TestNew_ConcurrentCreation constructs several Clients concurrently against distinct addresses
// and confirms there is no data race and every Client ends up with its own conn. Run with
// `go test -race` to exercise the race detector.
func TestNew_ConcurrentCreation(t *testing.T) {
	addrs := []string{
		"127.0.0.1:18143",
		"127.0.0.1:18144",
		"127.0.0.1:18145",
		"127.0.0.1:18146",
		"127.0.0.1:18147",
	}

	clients := make([]*Client, len(addrs))
	var wg sync.WaitGroup
	for i, addr := range addrs {
		wg.Add(1)
		go func(idx int, address string) {
			defer wg.Done()
			c, err := New(address)
			if err != nil {
				t.Errorf("New(%q) returned unexpected error: %v", address, err)
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
	InitWalletGRPC("127.0.0.1:18143")
	if grpcConn == nil {
		t.Fatal("InitWalletGRPC did not populate the package-level grpcConn")
	}
}

// fakeWalletServer (defined in wallet_test.go) implements just enough of
// tari_generated.WalletServer to exercise GetBalance and Transfer, in addition to the
// Identify/GetPaymentIdAddress/GetCompletedTransactions/StreamTransactionEvents methods used by
// that file's tests, over an in-memory bufconn listener.

// startFakeWallet (defined in wallet_test.go) spins up an in-memory GRPC server backed by
// bufconn, points the package-level grpcConn at it, and registers a cleanup that restores the
// prior grpcConn so tests don't leak state into each other.

// newBufconnClient spins up an in-memory GRPC server backed by bufconn and returns a *Client
// wrapping a connection to it, plus a cleanup func via t.Cleanup. Unlike startFakeWallet, this
// does not touch the package-level grpcConn — it's for testing the new per-connection Client
// type in isolation.
func newBufconnClient(t *testing.T, srv *fakeWalletServer) *Client {
	t.Helper()

	lis := bufconn.Listen(1024 * 1024)
	grpcSrv := grpc.NewServer()
	tari_generated.RegisterWalletServer(grpcSrv, srv)

	go func() {
		_ = grpcSrv.Serve(lis)
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

	t.Cleanup(func() {
		_ = conn.Close()
		grpcSrv.Stop()
		_ = lis.Close()
	})

	return &Client{conn: conn}
}

func TestGetBalances(t *testing.T) {
	startFakeWallet(t, &fakeWalletServer{
		balanceResp: &tari_generated.GetBalanceResponse{AvailableBalance: 12345},
	})

	resp, err := GetBalances()
	if err != nil {
		t.Fatalf("GetBalances returned error: %v", err)
	}
	if resp.GetAvailableBalance() != 12345 {
		t.Errorf("AvailableBalance = %d, want 12345", resp.GetAvailableBalance())
	}
}

// TestClient_GetBalances verifies the per-connection Client.GetBalances method behaves the same
// as the deprecated package-level GetBalances.
func TestClient_GetBalances(t *testing.T) {
	c := newBufconnClient(t, &fakeWalletServer{
		balanceResp: &tari_generated.GetBalanceResponse{AvailableBalance: 12345},
	})

	resp, err := c.GetBalances(context.Background())
	if err != nil {
		t.Fatalf("Client.GetBalances returned error: %v", err)
	}
	if resp.GetAvailableBalance() != 12345 {
		t.Errorf("AvailableBalance = %d, want 12345", resp.GetAvailableBalance())
	}
}

// NOTE: TestSendTransactions_AmbiguousBroadcastErrors, TestSendTransactions_NonAmbiguousErrorPassesThrough,
// TestSendTransactions_NilErrorWithMixedResults, and TestSendTransactions_RespectsContextCancellation
// below all pass singleTx=false to (*Client).SendTransactions. That value is arbitrary/irrelevant
// for their purposes: they exercise transport-error classification and ctx plumbing, not
// singleTx batching behavior, and none of them assert on the SingleTx field the fake server
// received. Dedicated coverage for singleTx actually reaching the TransferRequest lives in
// TestClient_SendTransactions_SingleTxFalse and TestClient_SendTransactions_SingleTxTrue below,
// mirroring the deprecated function's TestSendTransactions_SingleTxFalse/True in wallet_test.go.

// TestSendTransactions_AmbiguousBroadcastErrors verifies that DeadlineExceeded, Unavailable, and
// Canceled transport errors from the underlying Transfer RPC all get wrapped in
// ErrAmbiguousBroadcast, and that the original gRPC error remains inspectable via errors.Unwrap.
func TestSendTransactions_AmbiguousBroadcastErrors(t *testing.T) {
	cases := []struct {
		name string
		code codes.Code
	}{
		{"DeadlineExceeded", codes.DeadlineExceeded},
		{"Unavailable", codes.Unavailable},
		{"Canceled", codes.Canceled},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wantErr := status.Error(tc.code, "simulated "+tc.name)
			c := newBufconnClient(t, &fakeWalletServer{
				transferFn: func(ctx context.Context, req *tari_generated.TransferRequest) (*tari_generated.TransferResponse, error) {
					return nil, wantErr
				},
			})

			_, err := c.SendTransactions(context.Background(), nil, false)
			if err == nil {
				t.Fatal("SendTransactions returned nil error, want an ambiguous-broadcast error")
			}
			if !errors.Is(err, ErrAmbiguousBroadcast) {
				t.Errorf("errors.Is(err, ErrAmbiguousBroadcast) = false, want true (err: %v)", err)
			}
			// The original gRPC status must still be inspectable via status.FromError, which
			// (since Go 1.20) traverses multi-%w-wrapped error trees the same way errors.Is/As
			// do, proving the original error is still reachable through the wrapping.
			gotSt, ok := status.FromError(err)
			if !ok {
				t.Fatalf("status.FromError(err) ok = false, want true (err: %v)", err)
			}
			if gotSt.Code() != tc.code {
				t.Errorf("status.FromError(err).Code() = %v, want %v", gotSt.Code(), tc.code)
			}
		})
	}
}

// TestSendTransactions_NonAmbiguousErrorPassesThrough verifies that an InvalidArgument error
// (a genuinely safe-to-fail-fast case) is NOT wrapped in ErrAmbiguousBroadcast.
func TestSendTransactions_NonAmbiguousErrorPassesThrough(t *testing.T) {
	wantErr := status.Error(codes.InvalidArgument, "simulated invalid argument")
	c := newBufconnClient(t, &fakeWalletServer{
		transferFn: func(ctx context.Context, req *tari_generated.TransferRequest) (*tari_generated.TransferResponse, error) {
			return nil, wantErr
		},
	})

	_, err := c.SendTransactions(context.Background(), nil, false)
	if err == nil {
		t.Fatal("SendTransactions returned nil error, want an InvalidArgument error")
	}
	if errors.Is(err, ErrAmbiguousBroadcast) {
		t.Errorf("errors.Is(err, ErrAmbiguousBroadcast) = true, want false for a non-ambiguous InvalidArgument error (err: %v)", err)
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.InvalidArgument {
		t.Errorf("status.FromError(err) = (%v, %v), want (InvalidArgument, true)", st, ok)
	}
}

// TestSendTransactions_NilErrorWithMixedResults confirms that a nil top-level error from
// Transfer does NOT imply every recipient succeeded: resp.Results can (and here does) carry a
// mix of IsSuccess: true/false entries, unmodified, alongside a nil error.
func TestSendTransactions_NilErrorWithMixedResults(t *testing.T) {
	mixed := &tari_generated.TransferResponse{
		Results: []*tari_generated.TransferResult{
			{Address: "addr-1", TransactionId: 1, IsSuccess: true},
			{Address: "addr-2", TransactionId: 2, IsSuccess: false, FailureMessage: "insufficient funds"},
			{Address: "addr-3", TransactionId: 3, IsSuccess: true},
		},
	}
	c := newBufconnClient(t, &fakeWalletServer{
		transferFn: func(ctx context.Context, req *tari_generated.TransferRequest) (*tari_generated.TransferResponse, error) {
			return mixed, nil
		},
	})

	resp, err := c.SendTransactions(context.Background(), nil, false)
	if err != nil {
		t.Fatalf("SendTransactions returned unexpected error: %v", err)
	}
	if len(resp.GetResults()) != 3 {
		t.Fatalf("len(resp.Results) = %d, want 3", len(resp.GetResults()))
	}
	if resp.GetResults()[0].GetIsSuccess() != true || resp.GetResults()[1].GetIsSuccess() != false || resp.GetResults()[2].GetIsSuccess() != true {
		t.Errorf("resp.Results IsSuccess pattern was modified, got: %v, %v, %v",
			resp.GetResults()[0].GetIsSuccess(), resp.GetResults()[1].GetIsSuccess(), resp.GetResults()[2].GetIsSuccess())
	}
	if resp.GetResults()[1].GetFailureMessage() != "insufficient funds" {
		t.Errorf("resp.Results[1].FailureMessage = %q, want %q", resp.GetResults()[1].GetFailureMessage(), "insufficient funds")
	}
}

// TestSendTransactions_RespectsContextCancellation proves ctx is actually wired through to the
// underlying RPC call (not just accepted and silently discarded): calling SendTransactions with
// an already-canceled context.Context against the bufconn fake server must fail with a
// context.Canceled/codes.Canceled-flavored error rather than succeeding.
func TestSendTransactions_RespectsContextCancellation(t *testing.T) {
	c := newBufconnClient(t, &fakeWalletServer{})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := c.SendTransactions(ctx, nil, false)
	if err == nil {
		t.Fatal("SendTransactions with an already-canceled context returned nil error, want a cancellation error")
	}
	if !errors.Is(err, context.Canceled) {
		if st, ok := status.FromError(err); !ok || st.Code() != codes.Canceled {
			t.Errorf("expected a context.Canceled/codes.Canceled-flavored error, got: %v", err)
		}
	}
	// A canceled context is exactly the ambiguous case per the classification rules.
	if !errors.Is(err, ErrAmbiguousBroadcast) {
		t.Errorf("errors.Is(err, ErrAmbiguousBroadcast) = false, want true for a canceled-context error (err: %v)", err)
	}
}

// TestClient_SendTransactions_SingleTxFalse verifies that calling (*Client).SendTransactions
// with singleTx=false produces a TransferRequest with SingleTx: false and the given recipients,
// as observed by the fake server's transferFn. Mirrors the deprecated package-level function's
// TestSendTransactions_SingleTxFalse in wallet_test.go, adapted for the ctx-taking Client method.
func TestClient_SendTransactions_SingleTxFalse(t *testing.T) {
	var gotReq *tari_generated.TransferRequest
	c := newBufconnClient(t, &fakeWalletServer{
		transferFn: func(ctx context.Context, req *tari_generated.TransferRequest) (*tari_generated.TransferResponse, error) {
			gotReq = req
			return &tari_generated.TransferResponse{}, nil
		},
	})

	recipients := []*tari_generated.PaymentRecipient{
		{Address: "addr-1", Amount: 100},
		{Address: "addr-2", Amount: 200},
	}

	_, err := c.SendTransactions(context.Background(), recipients, false)
	if err != nil {
		t.Fatalf("SendTransactions returned unexpected error: %v", err)
	}
	if gotReq == nil {
		t.Fatal("server never recorded a TransferRequest")
	}
	if gotReq.GetSingleTx() != false {
		t.Errorf("req.SingleTx = %v, want false", gotReq.GetSingleTx())
	}
	if len(gotReq.GetRecipients()) != 2 {
		t.Fatalf("len(req.Recipients) = %d, want 2", len(gotReq.GetRecipients()))
	}
	if gotReq.GetRecipients()[0].GetAddress() != "addr-1" || gotReq.GetRecipients()[1].GetAddress() != "addr-2" {
		t.Errorf("req.Recipients addresses = %q, %q, want %q, %q",
			gotReq.GetRecipients()[0].GetAddress(), gotReq.GetRecipients()[1].GetAddress(), "addr-1", "addr-2")
	}
}

// TestClient_SendTransactions_SingleTxTrue verifies that calling (*Client).SendTransactions
// with singleTx=true produces a TransferRequest with SingleTx: true and the given recipients,
// as observed by the fake server's transferFn. Mirrors the deprecated package-level function's
// TestSendTransactions_SingleTxTrue in wallet_test.go, adapted for the ctx-taking Client method.
func TestClient_SendTransactions_SingleTxTrue(t *testing.T) {
	var gotReq *tari_generated.TransferRequest
	c := newBufconnClient(t, &fakeWalletServer{
		transferFn: func(ctx context.Context, req *tari_generated.TransferRequest) (*tari_generated.TransferResponse, error) {
			gotReq = req
			return &tari_generated.TransferResponse{}, nil
		},
	})

	recipients := []*tari_generated.PaymentRecipient{
		{Address: "addr-1", Amount: 100},
		{Address: "addr-2", Amount: 200},
	}

	_, err := c.SendTransactions(context.Background(), recipients, true)
	if err != nil {
		t.Fatalf("SendTransactions returned unexpected error: %v", err)
	}
	if gotReq == nil {
		t.Fatal("server never recorded a TransferRequest")
	}
	if gotReq.GetSingleTx() != true {
		t.Errorf("req.SingleTx = %v, want true", gotReq.GetSingleTx())
	}
	if len(gotReq.GetRecipients()) != 2 {
		t.Fatalf("len(req.Recipients) = %d, want 2", len(gotReq.GetRecipients()))
	}
	if gotReq.GetRecipients()[0].GetAddress() != "addr-1" || gotReq.GetRecipients()[1].GetAddress() != "addr-2" {
		t.Errorf("req.Recipients addresses = %q, %q, want %q, %q",
			gotReq.GetRecipients()[0].GetAddress(), gotReq.GetRecipients()[1].GetAddress(), "addr-1", "addr-2")
	}
}

// TestSplitTransferResults covers SplitTransferResults' partitioning logic, including the edge
// cases called out in the fix brief: nil resp, empty Results, all-success, all-failure, and
// mixed.
func TestSplitTransferResults(t *testing.T) {
	r1 := &tari_generated.TransferResult{Address: "a1", IsSuccess: true}
	r2 := &tari_generated.TransferResult{Address: "a2", IsSuccess: false}
	r3 := &tari_generated.TransferResult{Address: "a3", IsSuccess: true}
	r4 := &tari_generated.TransferResult{Address: "a4", IsSuccess: false}

	t.Run("nil response", func(t *testing.T) {
		succeeded, failed := SplitTransferResults(nil)
		if succeeded != nil {
			t.Errorf("succeeded = %v, want nil", succeeded)
		}
		if failed != nil {
			t.Errorf("failed = %v, want nil", failed)
		}
	})

	t.Run("empty results", func(t *testing.T) {
		succeeded, failed := SplitTransferResults(&tari_generated.TransferResponse{Results: nil})
		if len(succeeded) != 0 {
			t.Errorf("len(succeeded) = %d, want 0", len(succeeded))
		}
		if len(failed) != 0 {
			t.Errorf("len(failed) = %d, want 0", len(failed))
		}
	})

	t.Run("all success", func(t *testing.T) {
		succeeded, failed := SplitTransferResults(&tari_generated.TransferResponse{Results: []*tari_generated.TransferResult{r1, r3}})
		if len(succeeded) != 2 || len(failed) != 0 {
			t.Fatalf("got succeeded=%d failed=%d, want succeeded=2 failed=0", len(succeeded), len(failed))
		}
		if succeeded[0] != r1 || succeeded[1] != r3 {
			t.Error("succeeded slice does not hold the expected pointer identities")
		}
	})

	t.Run("all failure", func(t *testing.T) {
		succeeded, failed := SplitTransferResults(&tari_generated.TransferResponse{Results: []*tari_generated.TransferResult{r2, r4}})
		if len(succeeded) != 0 || len(failed) != 2 {
			t.Fatalf("got succeeded=%d failed=%d, want succeeded=0 failed=2", len(succeeded), len(failed))
		}
		if failed[0] != r2 || failed[1] != r4 {
			t.Error("failed slice does not hold the expected pointer identities")
		}
	})

	t.Run("mixed", func(t *testing.T) {
		succeeded, failed := SplitTransferResults(&tari_generated.TransferResponse{Results: []*tari_generated.TransferResult{r1, r2, r3, r4}})
		if len(succeeded) != 2 {
			t.Errorf("len(succeeded) = %d, want 2", len(succeeded))
		}
		if len(failed) != 2 {
			t.Errorf("len(failed) = %d, want 2", len(failed))
		}
		if succeeded[0] != r1 || succeeded[1] != r3 {
			t.Error("succeeded slice does not hold the expected pointer identities")
		}
		if failed[0] != r2 || failed[1] != r4 {
			t.Error("failed slice does not hold the expected pointer identities")
		}
	})
}
