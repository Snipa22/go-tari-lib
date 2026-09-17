package walletGRPC

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
)

// ErrAmbiguousBroadcast is wrapped into the error returned by (*Client).SendTransactions
// whenever the underlying Transfer RPC fails in a way that does NOT tell us whether the
// transaction was actually broadcast before the failure occurred (gRPC codes.DeadlineExceeded,
// codes.Unavailable, codes.Canceled, or any non-gRPC-status transport/connection error). Callers
// must NOT treat these as safe to blindly retry: a naive retry-on-any-error loop risks a double
// spend/double payout if the original request already reached the wallet and broadcast a
// transaction before the response was lost. Use errors.Is(err, ErrAmbiguousBroadcast) to detect
// this case and fall back to a reconciliation step (e.g. checking transaction history/state)
// before deciding whether to resend.
var ErrAmbiguousBroadcast = errors.New("walletGRPC: ambiguous broadcast result, transaction may have already been submitted — do not blindly retry")

// Client wraps an independent *grpc.ClientConn to a single Tari wallet. Unlike the deprecated
// package-level functions below, a Client holds no shared/global state, so it is safe to create
// and use as many Clients as needed concurrently (e.g. one per wallet in a payout fleet).
type Client struct {
	conn *grpc.ClientConn
}

// New dials walletAddress and returns a Client wrapping its own independent connection. Safe to
// create as many Clients as needed for concurrent use against different wallets.
//
// opts lets callers override dial options (e.g. TLS credentials) instead of always using
// insecure.NewCredentials(); pass none to get the same insecure default the deprecated
// package-level API used.
//
// Note: grpc.NewClient performs no I/O and does not block; the connection is established lazily
// on first RPC use.
func New(walletAddress string, opts ...grpc.DialOption) (*Client, error) {
	dialOpts := make([]grpc.DialOption, 0, len(opts)+1)
	if len(opts) == 0 {
		dialOpts = append(dialOpts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		dialOpts = append(dialOpts, opts...)
	}
	conn, err := grpc.NewClient(walletAddress, dialOpts...)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

// Close closes the underlying gRPC connection held by this Client.
func (c *Client) Close() error {
	return c.conn.Close()
}

// classifyTransferErr wraps a transport-level error returned by the Transfer RPC with
// ErrAmbiguousBroadcast when the failure mode gives no signal about whether the wallet actually
// broadcast the transaction before the error occurred (timeouts, unavailability, cancellation,
// or any non-gRPC-status error such as a connection refused before any RPC frame was exchanged —
// which carries the exact same "did it actually reach the server" uncertainty as a timeout).
// Every other gRPC status code (including codes.InvalidArgument, and codes.OK meaning no error
// at all) is returned unwrapped, since those are the genuinely safe-to-retry-or-fail-fast cases.
func classifyTransferErr(err error) error {
	if err == nil {
		return nil
	}
	st, ok := status.FromError(err)
	if !ok {
		// A non-gRPC-status error (e.g. dial/connection-level failure) has the same "did it
		// actually reach the server" uncertainty as a timeout — treat it as ambiguous too.
		return fmt.Errorf("%w: %w", ErrAmbiguousBroadcast, err)
	}
	switch st.Code() {
	case codes.DeadlineExceeded, codes.Unavailable, codes.Canceled:
		return fmt.Errorf("%w: %w", ErrAmbiguousBroadcast, err)
	default:
		return err
	}
}

// SendTransactions sends transactions to the wallet via the Transfer RPC.
//
// IMPORTANT: err == nil does NOT mean every recipient succeeded. The wallet's Transfer RPC
// reports success/failure per recipient in resp.Results ([]*tari_generated.TransferResult);
// callers MUST inspect each result's IsSuccess/FailureMessage/TransactionId fields (or use
// SplitTransferResults) rather than assuming a nil top-level error means the whole batch
// succeeded. A caller that only checks the top-level error can silently miss per-recipient
// failures.
//
// If the underlying Transfer RPC itself fails at the transport level with a gRPC status of
// DeadlineExceeded, Unavailable, or Canceled — or with a non-gRPC-status error such as a
// connection failure before any RPC frame was exchanged — the returned error wraps
// ErrAmbiguousBroadcast (checkable via errors.Is) because it is impossible to know whether the
// wallet already broadcast the transaction before the failure occurred. Do not blindly retry in
// that case. Any other error (including codes.InvalidArgument) is returned as-is: those cases
// are safe to retry or fail fast, since the wallet either rejected the request outright or never
// received it.
func (c *Client) SendTransactions(ctx context.Context, transactions []*tari_generated.PaymentRecipient) (*tari_generated.TransferResponse, error) {
	client := tari_generated.NewWalletClient(c.conn)
	resp, err := client.Transfer(ctx, &tari_generated.TransferRequest{
		Recipients: transactions,
	})
	if err != nil {
		return resp, classifyTransferErr(err)
	}
	return resp, nil
}

// SplitTransferResults separates a TransferResponse's per-recipient results into successes and
// failures based on each TransferResult's IsSuccess field. Handles resp == nil and an empty
// Results slice gracefully, returning nil slices rather than panicking. The returned slices hold
// the same *tari_generated.TransferResult pointers found in resp.Results (no copying).
func SplitTransferResults(resp *tari_generated.TransferResponse) (succeeded, failed []*tari_generated.TransferResult) {
	if resp == nil {
		return nil, nil
	}
	for _, result := range resp.Results {
		if result.GetIsSuccess() {
			succeeded = append(succeeded, result)
		} else {
			failed = append(failed, result)
		}
	}
	return succeeded, failed
}

// GetTransactionsInBlock will return the top of the wallet if it's called with 0, otherwise it
// pushes the height to the GRPC call, though this doesn't seem to actually do anything. No
// sorting/order/etc is guaranteed, so callers need to parse, cache etc.
func (c *Client) GetTransactionsInBlock(ctx context.Context, blockHeight uint64) ([]*tari_generated.TransactionInfo, error) {
	client := tari_generated.NewWalletClient(c.conn)
	var completedTxnsClient tari_generated.Wallet_GetCompletedTransactionsClient
	var err error
	if blockHeight == 0 {
		completedTxnsClient, err = client.GetCompletedTransactions(ctx, nil)
	} else {
		getBlockHeightTxns, err := client.GetBlockHeightTransactions(ctx, &tari_generated.GetBlockHeightTransactionsRequest{
			BlockHeight: blockHeight,
		})
		if err != nil {
			return nil, err
		}
		return getBlockHeightTxns.Transactions, nil
	}
	if err != nil {
		return nil, err
	}

	resp := make([]*tari_generated.TransactionInfo, 0)
	for {
		txnResp, err := completedTxnsClient.Recv()
		if err != nil {
			if err == io.EOF {
				return resp, nil
			}
			return nil, err
		}
		resp = append(resp, txnResp.Transaction)
	}
}

// SubmitCoinSplitRequest wraps the CoinSplit GRPC call so we can split coins easier
func (c *Client) SubmitCoinSplitRequest(ctx context.Context, splitAmt int, numSplits int) (*tari_generated.CoinSplitResponse, error) {
	client := tari_generated.NewWalletClient(c.conn)
	return client.CoinSplit(ctx, &tari_generated.CoinSplitRequest{
		AmountPerSplit: uint64(splitAmt),
		SplitCount:     uint64(numSplits),
		FeePerGram:     5,
		LockHeight:     0,
		PaymentId:      nil,
	})
}

// GetBalances wraps the GetBalances GRPC call
func (c *Client) GetBalances(ctx context.Context) (*tari_generated.GetBalanceResponse, error) {
	client := tari_generated.NewWalletClient(c.conn)
	return client.GetBalance(ctx, &tari_generated.GetBalanceRequest{})
}

// GetTransactionInfoByID wraps the GetTransactionInfo call in GRPC, one at a time
func (c *Client) GetTransactionInfoByID(ctx context.Context, transactionID uint64) (*tari_generated.TransactionInfo, error) {
	client := tari_generated.NewWalletClient(c.conn)
	txns, err := client.GetTransactionInfo(ctx, &tari_generated.GetTransactionInfoRequest{
		TransactionIds: []uint64{transactionID},
	})
	if err != nil || len(txns.Transactions) == 0 {
		return nil, err
	}
	return txns.Transactions[0], nil
}

// RevalidateAllTransactions wraps the RevalidateAllTransactions GRPC call.
func (c *Client) RevalidateAllTransactions(ctx context.Context) (*tari_generated.RevalidateResponse, error) {
	client := tari_generated.NewWalletClient(c.conn)
	return client.RevalidateAllTransactions(ctx, &tari_generated.RevalidateRequest{})
}

// ValidateAllTransactions wraps the ValidateAllTransactions GRPC call.
func (c *Client) ValidateAllTransactions(ctx context.Context) (*tari_generated.ValidateResponse, error) {
	client := tari_generated.NewWalletClient(c.conn)
	return client.ValidateAllTransactions(ctx, &tari_generated.ValidateRequest{})
}

// GetWalletState wraps the GetState call on the wallet GRPC
func (c *Client) GetWalletState(ctx context.Context) (*tari_generated.GetStateResponse, error) {
	client := tari_generated.NewWalletClient(c.conn)
	return client.GetState(ctx, &tari_generated.GetStateRequest{})
}

// GetWalletConnectivity wraps the CheckConnectivity call
func (c *Client) GetWalletConnectivity(ctx context.Context) (*tari_generated.CheckConnectivityResponse, error) {
	client := tari_generated.NewWalletClient(c.conn)
	return client.CheckConnectivity(ctx, &tari_generated.GetConnectivityRequest{})
}

// GetAddresses gets the addresses for the wallet
func (c *Client) GetAddresses(ctx context.Context) (*tari_generated.GetCompleteAddressResponse, error) {
	client := tari_generated.NewWalletClient(c.conn)
	return client.GetCompleteAddress(ctx, nil)
}

// Identify wraps the Identify GRPC call, returning the wallet node's identity information.
func (c *Client) Identify(ctx context.Context) (*tari_generated.GetIdentityResponse, error) {
	client := tari_generated.NewWalletClient(c.conn)
	return client.Identify(ctx, &tari_generated.GetIdentityRequest{})
}

// GetPaymentIdAddress wraps the GetPaymentIdAddress GRPC call, resolving the wallet address tied
// to a given payment ID (order reference string).
func (c *Client) GetPaymentIdAddress(ctx context.Context, paymentID string) (*tari_generated.GetCompleteAddressResponse, error) {
	client := tari_generated.NewWalletClient(c.conn)
	return client.GetPaymentIdAddress(ctx, &tari_generated.GetPaymentIdAddressRequest{
		PaymentId: []byte(paymentID),
	})
}

// GetCompletedTransactionsByPaymentID wraps the GetCompletedTransactions GRPC call, filtering to
// transactions tagged with the given payment ID (order reference string), and drains the
// resulting stream into a slice.
func (c *Client) GetCompletedTransactionsByPaymentID(ctx context.Context, paymentID string) ([]*tari_generated.TransactionInfo, error) {
	client := tari_generated.NewWalletClient(c.conn)
	completedTxnsClient, err := client.GetCompletedTransactions(ctx, &tari_generated.GetCompletedTransactionsRequest{
		PaymentId: &tari_generated.UserPaymentId{Utf8String: paymentID},
	})
	if err != nil {
		return nil, err
	}

	resp := make([]*tari_generated.TransactionInfo, 0)
	for {
		txnResp, err := completedTxnsClient.Recv()
		if err != nil {
			if err == io.EOF {
				return resp, nil
			}
			return nil, err
		}
		resp = append(resp, txnResp.Transaction)
	}
}

// StreamTransactionEvents wraps the StreamTransactionEvents GRPC call. It forwards each event
// received off the stream onto the returned event channel, and forwards any terminal error
// (other than a clean io.EOF) onto the returned error channel. Both channels are closed when the
// stream ends. Callers should cancel ctx to stop the stream; the underlying goroutine exits
// cleanly once Recv() surfaces the resulting cancellation error.
func (c *Client) StreamTransactionEvents(ctx context.Context) (<-chan *tari_generated.TransactionEventResponse, <-chan error) {
	client := tari_generated.NewWalletClient(c.conn)
	events := make(chan *tari_generated.TransactionEventResponse, 16)
	errs := make(chan error, 1)

	stream, err := client.StreamTransactionEvents(ctx, &tari_generated.TransactionEventRequest{})
	if err != nil {
		errs <- err
		close(events)
		close(errs)
		return events, errs
	}

	go func() {
		defer close(events)
		defer close(errs)
		for {
			event, err := stream.Recv()
			if err != nil {
				if err != io.EOF {
					errs <- err
				}
				return
			}
			select {
			case events <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	return events, errs
}
