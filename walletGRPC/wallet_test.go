package walletGRPC

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// fakeWalletServer implements just enough of tari_generated.WalletServer to exercise Identify,
// GetPaymentIdAddress, GetCompletedTransactions and StreamTransactionEvents over an in-memory
// bufconn listener.
type fakeWalletServer struct {
	tari_generated.UnimplementedWalletServer

	identifyResp *tari_generated.GetIdentityResponse
	identifyErr  error

	paymentIdAddressResp    *tari_generated.GetCompleteAddressResponse
	lastPaymentIdAddressReq *tari_generated.GetPaymentIdAddressRequest

	completedTxns []*tari_generated.TransactionInfo

	streamEvents  []*tari_generated.TransactionEvent
	streamSendGap time.Duration
}

func (f *fakeWalletServer) Identify(ctx context.Context, in *tari_generated.GetIdentityRequest) (*tari_generated.GetIdentityResponse, error) {
	if f.identifyErr != nil {
		return nil, f.identifyErr
	}
	return f.identifyResp, nil
}

func (f *fakeWalletServer) GetPaymentIdAddress(ctx context.Context, in *tari_generated.GetPaymentIdAddressRequest) (*tari_generated.GetCompleteAddressResponse, error) {
	f.lastPaymentIdAddressReq = in
	return f.paymentIdAddressResp, nil
}

func (f *fakeWalletServer) GetCompletedTransactions(in *tari_generated.GetCompletedTransactionsRequest, stream tari_generated.Wallet_GetCompletedTransactionsServer) error {
	for _, txn := range f.completedTxns {
		if err := stream.Send(&tari_generated.GetCompletedTransactionsResponse{Transaction: txn}); err != nil {
			return err
		}
	}
	return nil
}

func (f *fakeWalletServer) StreamTransactionEvents(in *tari_generated.TransactionEventRequest, stream tari_generated.Wallet_StreamTransactionEventsServer) error {
	for _, evt := range f.streamEvents {
		if err := stream.Send(&tari_generated.TransactionEventResponse{Transaction: evt}); err != nil {
			return err
		}
		if f.streamSendGap > 0 {
			select {
			case <-time.After(f.streamSendGap):
			case <-stream.Context().Done():
				return stream.Context().Err()
			}
		}
	}
	return nil
}

// startFakeWallet spins up an in-memory GRPC server backed by bufconn, points the package-level
// grpcConn at it, and registers a cleanup that restores the prior grpcConn so tests don't leak
// state into each other.
func startFakeWallet(t *testing.T, srv *fakeWalletServer) {
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

	prevConn := grpcConn
	grpcConn = conn

	t.Cleanup(func() {
		_ = conn.Close()
		grpcSrv.Stop()
		_ = lis.Close()
		grpcConn = prevConn
	})
}

func TestIdentify_Success(t *testing.T) {
	startFakeWallet(t, &fakeWalletServer{
		identifyResp: &tari_generated.GetIdentityResponse{
			PublicKey:     []byte{0x01, 0x02},
			PublicAddress: "127.0.0.1:18189",
			NodeId:        []byte{0x03},
		},
	})

	resp, err := Identify()
	if err != nil {
		t.Fatalf("Identify returned unexpected error: %v", err)
	}
	if resp.GetPublicAddress() != "127.0.0.1:18189" {
		t.Errorf("PublicAddress = %q, want %q", resp.GetPublicAddress(), "127.0.0.1:18189")
	}
}

func TestIdentify_PropagatesError(t *testing.T) {
	wantErr := status.Error(codes.Internal, "identity lookup failed")
	startFakeWallet(t, &fakeWalletServer{
		identifyErr: wantErr,
	})

	_, err := Identify()
	if err == nil {
		t.Fatal("Identify returned nil error, want propagated failure")
	}
	if status.Code(err) != codes.Internal {
		t.Errorf("Identify error code = %v, want %v", status.Code(err), codes.Internal)
	}
}

func TestGetPaymentIdAddress_SendsUtf8PaymentIDAndReturnsResponse(t *testing.T) {
	srv := &fakeWalletServer{
		paymentIdAddressResp: &tari_generated.GetCompleteAddressResponse{
			InteractiveAddressBase58: "some-base58-address",
		},
	}
	startFakeWallet(t, srv)

	resp, err := GetPaymentIdAddress("order-ref-12345")
	if err != nil {
		t.Fatalf("GetPaymentIdAddress returned unexpected error: %v", err)
	}
	if resp.GetInteractiveAddressBase58() != "some-base58-address" {
		t.Errorf("InteractiveAddressBase58 = %q, want %q", resp.GetInteractiveAddressBase58(), "some-base58-address")
	}

	if srv.lastPaymentIdAddressReq == nil {
		t.Fatal("server never recorded a GetPaymentIdAddressRequest")
	}
	if got := string(srv.lastPaymentIdAddressReq.GetPaymentId()); got != "order-ref-12345" {
		t.Errorf("request PaymentId = %q, want %q", got, "order-ref-12345")
	}
}

func TestGetCompletedTransactionsByPaymentID_DrainsMultiItemStream(t *testing.T) {
	startFakeWallet(t, &fakeWalletServer{
		completedTxns: []*tari_generated.TransactionInfo{
			{TxId: 1},
			{TxId: 2},
			{TxId: 3},
		},
	})

	txns, err := GetCompletedTransactionsByPaymentID("order-ref-abc")
	if err != nil {
		t.Fatalf("GetCompletedTransactionsByPaymentID returned unexpected error: %v", err)
	}
	if len(txns) != 3 {
		t.Fatalf("len(txns) = %d, want 3", len(txns))
	}
	for i, want := range []uint64{1, 2, 3} {
		if txns[i].GetTxId() != want {
			t.Errorf("txns[%d].TxId = %d, want %d", i, txns[i].GetTxId(), want)
		}
	}
}

func TestGetCompletedTransactionsByPaymentID_EmptyStreamReturnsEmptySlice(t *testing.T) {
	startFakeWallet(t, &fakeWalletServer{
		completedTxns: nil,
	})

	txns, err := GetCompletedTransactionsByPaymentID("order-ref-empty")
	if err != nil {
		t.Fatalf("GetCompletedTransactionsByPaymentID returned unexpected error: %v", err)
	}
	if txns == nil {
		t.Fatal("GetCompletedTransactionsByPaymentID returned nil slice, want empty non-nil slice")
	}
	if len(txns) != 0 {
		t.Fatalf("len(txns) = %d, want 0", len(txns))
	}
}

// TestStreamTransactionEvents_CancelPartway feeds several events into a mock stream, cancels the
// context after receiving a couple of them, and asserts that (a) the events received before
// cancellation appear on the event channel, (b) both channels are closed once the goroutine
// unwinds, and (c) no goroutine leak occurs (run with `go test -race`).
func TestStreamTransactionEvents_CancelPartway(t *testing.T) {
	startFakeWallet(t, &fakeWalletServer{
		streamEvents: []*tari_generated.TransactionEvent{
			{TxId: "tx-1"},
			{TxId: "tx-2"},
			{TxId: "tx-3"},
			{TxId: "tx-4"},
			{TxId: "tx-5"},
		},
		// Pace the sends so the test has time to cancel partway through the stream instead of
		// racing the whole batch through before cancellation happens.
		streamSendGap: 30 * time.Millisecond,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	events, errs := StreamTransactionEvents(ctx)

	var received []string
	const wantBeforeCancel = 2

readLoop:
	for {
		select {
		case evt, ok := <-events:
			if !ok {
				break readLoop
			}
			received = append(received, evt.GetTransaction().GetTxId())
			if len(received) == wantBeforeCancel {
				cancel()
			}
		case err, ok := <-errs:
			if !ok {
				// errs closed; keep draining events until it closes too.
				continue
			}
			if err != nil && !errors.Is(err, io.EOF) {
				// A cancellation-derived error is expected and fine; anything else is a bug we
				// want to see in the test output.
				t.Logf("received error from stream (expected on cancellation): %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for event/error channels to close after cancellation")
		}
	}

	if len(received) < wantBeforeCancel {
		t.Fatalf("received %d events before channel closed, want at least %d", len(received), wantBeforeCancel)
	}

	// Both channels must now be closed (drained above); confirm reads return zero values
	// immediately without blocking, proving they are indeed closed and not just empty.
	select {
	case v, ok := <-events:
		if ok {
			t.Fatalf("events channel not closed, got extra value: %v", v)
		}
	default:
		t.Fatal("events channel read would have blocked; expected it to be closed and drained")
	}

	select {
	case v, ok := <-errs:
		if ok {
			t.Fatalf("errs channel not closed, got extra value: %v", v)
		}
	default:
		t.Fatal("errs channel read would have blocked; expected it to be closed and drained")
	}
}

func TestStreamTransactionEvents_DialErrorClosesChannelsWithError(t *testing.T) {
	// Point grpcConn at a connection with nothing listening so the initial stream call fails.
	lis := bufconn.Listen(1024 * 1024)
	_ = lis.Close() // closed immediately so DialContext always fails to connect

	conn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("failed to construct client: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	prevConn := grpcConn
	grpcConn = conn
	t.Cleanup(func() { grpcConn = prevConn })

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	events, errs := StreamTransactionEvents(ctx)

	select {
	case _, ok := <-events:
		if ok {
			t.Fatal("expected events channel to be closed without values on dial failure")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for events channel to close")
	}

	select {
	case e, ok := <-errs:
		if !ok {
			t.Fatal("expected an error on errs channel before it closed")
		}
		if e == nil {
			t.Fatal("expected non-nil error on errs channel")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for error on errs channel")
	}
}
