package walletGRPC

import (
	"context"
	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
)

var grpcWalletAddress string
var grpcConn *grpc.ClientConn

func InitWalletGRPC(walletAddress string) {
	grpcWalletAddress = walletAddress
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	grpcConn, _ = grpc.NewClient(grpcWalletAddress, opts...)
}

// SendTransactions sends the transactions to the wallet
func SendTransactions(transactions []*tari_generated.PaymentRecipient) (*tari_generated.TransferResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.Transfer(context.Background(), &tari_generated.TransferRequest{
		Recipients: transactions,
	})
}

// GetTransactionsInBlock will return the top of the wallet if it's called with 0, otherwise it pushes the height to
// the GRPC call, though this doesn't seem to actually do anything.  No sorting/order/etc is guaranteed, so callers
// need to parse, cache etc.
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
func GetBalances() (*tari_generated.GetBalanceResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.GetBalance(context.Background(), &tari_generated.GetBalanceRequest{})
}

// GetTransactionInfoByID wraps the GetTransactionInfo call in GRPC, one at a time
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

func RevalidateAllTransactions() (*tari_generated.RevalidateResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.RevalidateAllTransactions(context.Background(), &tari_generated.RevalidateRequest{})
}

func ValidateAllTransactions() (*tari_generated.ValidateResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.ValidateAllTransactions(context.Background(), &tari_generated.ValidateRequest{})
}

// GetWalletState wraps the GetState call on the wallet GRPC
func GetWalletState() (*tari_generated.GetStateResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.GetState(context.Background(), &tari_generated.GetStateRequest{})
}

// GetWalletConnectivity wraps the CheckConnectivity call
func GetWalletConnectivity() (*tari_generated.CheckConnectivityResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.CheckConnectivity(context.Background(), &tari_generated.GetConnectivityRequest{})
}

// GetAddresses gets the addresses for the wallet
func GetAddresses() (*tari_generated.GetCompleteAddressResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.GetCompleteAddress(context.Background(), nil)
}

// Identify wraps the Identify GRPC call, returning the wallet node's identity information.
func Identify() (*tari_generated.GetIdentityResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.Identify(context.Background(), &tari_generated.GetIdentityRequest{})
}

// GetPaymentIdAddress wraps the GetPaymentIdAddress GRPC call, resolving the wallet address
// tied to a given payment ID (order reference string).
func GetPaymentIdAddress(paymentID string) (*tari_generated.GetCompleteAddressResponse, error) {
	client := tari_generated.NewWalletClient(grpcConn)
	return client.GetPaymentIdAddress(context.Background(), &tari_generated.GetPaymentIdAddressRequest{
		PaymentId: []byte(paymentID),
	})
}

// GetCompletedTransactionsByPaymentID wraps the GetCompletedTransactions GRPC call, filtering
// to transactions tagged with the given payment ID (order reference string), and drains the
// resulting stream into a slice.
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
