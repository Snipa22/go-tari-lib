package walletGRPC

import (
	"context"
	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
)

// ---------------------------------------------------------------------------------------------
// Deprecated package-level API below.
//
// These functions operate against a single shared package-level *grpc.ClientConn (grpcConn) set
// by InitWalletGRPC. This is NOT safe for any caller that needs to talk to more than one wallet
// concurrently: there is exactly one connection/address for the whole process, held as mutable
// global state with zero synchronization. Concurrent calls to InitWalletGRPC from different
// goroutines, or concurrent use of the functions below while another goroutine re-initializes
// the connection, is a data race.
//
// New code should use New(walletAddress) instead, which returns an independent *Client safe to
// create as many of as needed (e.g. one per wallet in a payout fleet), and whose methods take a
// caller-supplied context.Context so RPCs are properly cancellable/timeout-able.
// ---------------------------------------------------------------------------------------------

var grpcWalletAddress string
var grpcConn *grpc.ClientConn

// InitWalletGRPC initializes the package-level shared connection used by the deprecated
// package-level functions below (SendTransactions, GetBalances, etc.).
//
// Deprecated: this package-level singleton connection is NOT safe for concurrent use against
// multiple wallets — there is exactly one shared connection/address for the whole process. New
// code should use New(walletAddress) instead, which returns an independently-safe *Client for
// exactly one wallet's connection, safe to create as many of as needed.
func InitWalletGRPC(walletAddress string) {
	grpcWalletAddress = walletAddress
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	grpcConn, _ = grpc.NewClient(grpcWalletAddress, opts...)
}

// SendTransactions sends the transactions to the wallet.
//
// WARNING: err == nil does NOT mean every recipient succeeded — this deprecated function returns
// the raw TransferResponse with zero classification of per-recipient failures or of ambiguous
// "may have already broadcast" transport errors. Callers checking only the top-level error can
// silently miss per-recipient failures. Use (*Client).SendTransactions instead, which documents
// and handles both of those cases explicitly.
//
// Deprecated: uses the unsafe package-level shared connection and hardcodes context.Background()
// (uncancellable, no caller timeout). Use (*Client).SendTransactions instead.
func SendTransactions(transactions []*tari_generated.PaymentRecipient) (*tari_generated.TransferResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.Transfer(context.Background(), &tari_generated.TransferRequest{
		Recipients: transactions,
	})
}

// GetTransactionsInBlock will return the top of the wallet if it's called with 0, otherwise it pushes the height to
// the GRPC call, though this doesn't seem to actually do anything.  No sorting/order/etc is guaranteed, so callers
// need to parse, cache etc.
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetTransactionsInBlock instead.
func GetTransactionsInBlock(blockHeight uint64) ([]*tari_generated.TransactionInfo, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	var completedTxnsClient tari_generated.Wallet_GetCompletedTransactionsClient
	var err error
	if blockHeight == 0 {
		completedTxnsClient, err = client.GetCompletedTransactions(context.Background(), nil)
	} else {
		getBlockHeightTxns, err := client.GetBlockHeightTransactions(context.Background(), &tari_generated.GetBlockHeightTransactionsRequest{
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
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).SubmitCoinSplitRequest instead.
func SubmitCoinSplitRequest(splitAmt int, numSplits int) (*tari_generated.CoinSplitResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.CoinSplit(context.Background(), &tari_generated.CoinSplitRequest{
		AmountPerSplit: uint64(splitAmt),
		SplitCount:     uint64(numSplits),
		FeePerGram:     5,
		LockHeight:     0,
		PaymentId:      nil,
	})
}

// GetBalances wraps the GetBalances GRPC call
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetBalances instead.
func GetBalances() (*tari_generated.GetBalanceResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.GetBalance(context.Background(), &tari_generated.GetBalanceRequest{})
}

// GetTransactionInfoByID wraps the GetTransactionInfo call in GRPC, one at a time
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetTransactionInfoByID instead.
func GetTransactionInfoByID(transactionID uint64) (*tari_generated.TransactionInfo, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	txns, err := client.GetTransactionInfo(context.Background(), &tari_generated.GetTransactionInfoRequest{
		TransactionIds: []uint64{transactionID},
	})
	if err != nil || len(txns.Transactions) == 0 {
		return nil, err
	}
	return txns.Transactions[0], nil
}

// RevalidateAllTransactions wraps the RevalidateAllTransactions GRPC call.
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).RevalidateAllTransactions instead.
func RevalidateAllTransactions() (*tari_generated.RevalidateResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.RevalidateAllTransactions(context.Background(), &tari_generated.RevalidateRequest{})
}

// ValidateAllTransactions wraps the ValidateAllTransactions GRPC call.
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).ValidateAllTransactions instead.
func ValidateAllTransactions() (*tari_generated.ValidateResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.ValidateAllTransactions(context.Background(), &tari_generated.ValidateRequest{})
}

// GetWalletState wraps the GetState call on the wallet GRPC
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetWalletState instead.
func GetWalletState() (*tari_generated.GetStateResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.GetState(context.Background(), &tari_generated.GetStateRequest{})
}

// GetWalletConnectivity wraps the CheckConnectivity call
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetWalletConnectivity instead.
func GetWalletConnectivity() (*tari_generated.CheckConnectivityResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.CheckConnectivity(context.Background(), &tari_generated.GetConnectivityRequest{})
}

// GetAddresses gets the addresses for the wallet
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetAddresses instead.
func GetAddresses() (*tari_generated.GetCompleteAddressResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.GetCompleteAddress(context.Background(), nil)
}

// Identify wraps the Identify GRPC call, returning the wallet node's identity information.
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).Identify instead.
func Identify() (*tari_generated.GetIdentityResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.Identify(context.Background(), &tari_generated.GetIdentityRequest{})
}

// GetPaymentIdAddress wraps the GetPaymentIdAddress GRPC call, resolving the wallet address
// tied to a given payment ID (order reference string).
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetPaymentIdAddress instead.
func GetPaymentIdAddress(paymentID string) (*tari_generated.GetCompleteAddressResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.GetPaymentIdAddress(context.Background(), &tari_generated.GetPaymentIdAddressRequest{
		PaymentId: []byte(paymentID),
	})
}

// GetCompletedTransactionsByPaymentID wraps the GetCompletedTransactions GRPC call, filtering
// to transactions tagged with the given payment ID (order reference string), and drains the
// resulting stream into a slice.
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetCompletedTransactionsByPaymentID instead.
func GetCompletedTransactionsByPaymentID(paymentID string) ([]*tari_generated.TransactionInfo, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	completedTxnsClient, err := client.GetCompletedTransactions(context.Background(), &tari_generated.GetCompletedTransactionsRequest{
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
// (other than a clean io.EOF) onto the returned error channel. Both channels are closed when
// the stream ends. Callers should cancel ctx to stop the stream; the underlying goroutine exits
// cleanly once Recv() surfaces the resulting cancellation error.
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).StreamTransactionEvents instead.
func StreamTransactionEvents(ctx context.Context) (<-chan *tari_generated.TransactionEventResponse, <-chan error) {
	client := tari_generated.NewWalletClient(grpcConn)
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
