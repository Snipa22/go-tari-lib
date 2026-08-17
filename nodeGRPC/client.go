package nodeGRPC

import (
	"context"
	"github.com/Snipa22/go-tari-grpc-lib/v3/tari_generated"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
)

/*
RPC management notes, because of the way this works, we need to take a request, open a connection to the client, then
pass the response back to the client, everything is one-shot and every call is responsible for closing it's own conn

use minotari_app_grpc::tari_rpc::{
    GetNewBlockTemplateWithCoinbasesRequest,
    SubmitBlockRequest,
    SubmitBlockResponse,
};
*/

// Client wraps an independent *grpc.ClientConn to a single Tari base node. Unlike the
// package-level functions below, a Client holds no shared/global state, so it is safe to
// create and use as many Clients as needed concurrently (e.g. one per node in a fleet).
type Client struct {
	conn *grpc.ClientConn
}

// NewClient dials nodeAddress and returns a Client wrapping its own independent connection.
// Safe to create as many Clients as needed for concurrent use against different nodes.
//
// Note: grpc.NewClient performs no I/O and does not block; the connection is
// established lazily on first RPC use.
func NewClient(nodeAddress string) (*Client, error) {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	conn, err := grpc.NewClient(nodeAddress, opts...)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn}, nil
}

// Close closes the underlying gRPC connection held by this Client.
func (c *Client) Close() error {
	return c.conn.Close()
}

// GetTipInfo wraps the GetTipInfo GRPC call and handles the response from the upstream
func (c *Client) GetTipInfo() (*tari_generated.TipInfoResponse, error) {
	client := tari_generated.NewBaseNodeClient(c.conn)
	return client.GetTipInfo(context.Background(), &tari_generated.Empty{})
}

// GetBlockTemplate wraps the GetNewBlockTemplate call, requires the type of blockTemplate to generate
func (c *Client) GetBlockTemplate(algo *tari_generated.PowAlgo) (*tari_generated.NewBlockTemplateResponse, error) {
	client := tari_generated.NewBaseNodeClient(c.conn)
	return client.GetNewBlockTemplate(context.Background(), &tari_generated.NewBlockTemplateRequest{Algo: algo})
}

// GetBlockWithCoinbases wraps the GetNewBlockWithCoinbases, requires all data for the GRPC request
func (c *Client) GetBlockWithCoinbases(requestData *tari_generated.GetNewBlockWithCoinbasesRequest) (*tari_generated.GetNewBlockResult, error) {
	client := tari_generated.NewBaseNodeClient(c.conn)
	return client.GetNewBlockWithCoinbases(context.Background(), requestData)
}

// GetNewBlockTemplateWithCoinbases This incorrectly tells you that you're getting a template, but the response is a full block
func (c *Client) GetNewBlockTemplateWithCoinbases(requestData *tari_generated.GetNewBlockTemplateWithCoinbasesRequest) (*tari_generated.GetNewBlockResult, error) {
	client := tari_generated.NewBaseNodeClient(c.conn)
	return client.GetNewBlockTemplateWithCoinbases(context.Background(), requestData)
}

// GetNetworkState wraps the GetNetworkState RPC call
func (c *Client) GetNetworkState() (*tari_generated.GetNetworkStateResponse, error) {
	client := tari_generated.NewBaseNodeClient(c.conn)
	return client.GetNetworkState(context.Background(), nil)
}

// GetNewBlock wraps the GetNewBlock GRPC call
func (c *Client) GetNewBlock(requestData *tari_generated.NewBlockTemplate) (*tari_generated.GetNewBlockResult, error) {
	client := tari_generated.NewBaseNodeClient(c.conn)
	return client.GetNewBlock(context.Background(), requestData)
}

// GetBlockByHeight retrieves blocks, handles the streaming data, then returns the blocks as a slice
func (c *Client) GetBlockByHeight(blockIDs []uint64) ([]*tari_generated.Block, error) {
	client := tari_generated.NewBaseNodeClient(c.conn)
	active_client, err := client.GetBlocks(context.Background(), &tari_generated.GetBlocksRequest{Heights: blockIDs}, grpc.MaxCallRecvMsgSize(16*1024*1024))
	if err != nil {
		return nil, err
	}
	resp := make([]*tari_generated.Block, 0)
	for {
		blockResp, err := active_client.Recv()
		if err != nil {
			if err == io.EOF {
				return resp, nil
			}
			return nil, err
		}
		resp = append(resp, blockResp.GetBlock())
	}
}

// GetHeaderByHash wraps the GRPC call of the same name.
func (c *Client) GetHeaderByHash(blockHash []byte) (*tari_generated.BlockHeaderResponse, error) {
	client := tari_generated.NewBaseNodeClient(c.conn)
	return client.GetHeaderByHash(context.Background(), &tari_generated.GetHeaderByHashRequest{Hash: blockHash})
}

// SubmitBlock sends blocks to the daemon for processing
func (c *Client) SubmitBlock(requestData *tari_generated.Block) (*tari_generated.SubmitBlockResponse, error) {
	client := tari_generated.NewBaseNodeClient(c.conn)
	return client.SubmitBlock(context.Background(), requestData)
}

// GetNetworkDiff pulls the network diff of a given block, or it will just use tip if you give it a 0
func (c *Client) GetNetworkDiff(height uint64) (*tari_generated.NetworkDifficultyResponse, error) {
	client := tari_generated.NewBaseNodeClient(c.conn)
	var diffClient tari_generated.BaseNode_GetNetworkDifficultyClient
	var err error
	if height == 0 {
		diffClient, err = client.GetNetworkDifficulty(context.Background(), &tari_generated.HeightRequest{FromTip: 1})
	} else {
		diffClient, err = client.GetNetworkDifficulty(context.Background(), &tari_generated.HeightRequest{StartHeight: height, EndHeight: height})
	}
	if err != nil {
		return nil, err
	}
	return diffClient.Recv()
}

// GetNodeIdentity returns a list of valid rust identities for an opened GRPC node
func (c *Client) GetNodeIdentity() (*tari_generated.NodeIdentity, error) {
	client := tari_generated.NewBaseNodeClient(c.conn)
	return client.Identify(context.Background(), nil)
}

// ---------------------------------------------------------------------------------------------
// Deprecated package-level API below.
//
// These functions operate against a single shared package-level *grpc.ClientConn
// (grpcConn) set by InitNodeGRPC. This is NOT safe for any caller that needs to talk to more
// than one node concurrently: there is exactly one connection/address for the whole process,
// held as mutable global state with zero synchronization. Concurrent calls to InitNodeGRPC
// from different goroutines, or concurrent use of the functions below while another goroutine
// re-initializes the connection, is a data race.
//
// New code should use NewClient(nodeAddress) instead, which returns an independent *Client
// safe to create as many of as needed (e.g. one per node in a fleet poller).
// ---------------------------------------------------------------------------------------------

var grpcNodeAddress string
var grpcConn *grpc.ClientConn

// InitNodeGRPC initializes the package-level shared connection used by the deprecated
// package-level functions below (GetTipInfo, GetBlockTemplate, etc.).
//
// Deprecated: this package-level singleton connection is NOT safe for concurrent use against
// multiple nodes — there is exactly one shared connection/address for the whole process. New
// code should use NewClient(nodeAddress) instead, which returns an independently-safe *Client
// for exactly one node's connection, safe to create as many of as needed.
func InitNodeGRPC(nodeAddress string) {
	grpcNodeAddress = nodeAddress
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	grpcConn, _ = grpc.NewClient(grpcNodeAddress, opts...)
}

// GetTipInfo wraps the GetTipInfo GRPC call and handles the response from the upstream
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetTipInfo instead.
func GetTipInfo() (*tari_generated.TipInfoResponse, error) {
	client := tari_generated.NewBaseNodeClient(grpcConn)
	return client.GetTipInfo(context.Background(), &tari_generated.Empty{})
}

// GetBlockTemplate wraps the GetNewBlockTemplate call, requires the type of blockTemplate to generate
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetBlockTemplate instead.
func GetBlockTemplate(algo *tari_generated.PowAlgo) (*tari_generated.NewBlockTemplateResponse, error) {
	client := tari_generated.NewBaseNodeClient(grpcConn)
	return client.GetNewBlockTemplate(context.Background(), &tari_generated.NewBlockTemplateRequest{Algo: algo})
}

// GetBlockWithCoinbases wraps the GetNewBlockWithCoinbases, requires all data for the GRPC request
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetBlockWithCoinbases instead.
func GetBlockWithCoinbases(requestData *tari_generated.GetNewBlockWithCoinbasesRequest) (*tari_generated.GetNewBlockResult, error) {
	client := tari_generated.NewBaseNodeClient(grpcConn)
	return client.GetNewBlockWithCoinbases(context.Background(), requestData)
}

// GetNewBlockTemplateWithCoinbases This incorrectly tells you that you're getting a template, but the response is a full block
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetNewBlockTemplateWithCoinbases instead.
func GetNewBlockTemplateWithCoinbases(requestData *tari_generated.GetNewBlockTemplateWithCoinbasesRequest) (*tari_generated.GetNewBlockResult, error) {
	client := tari_generated.NewBaseNodeClient(grpcConn)
	return client.GetNewBlockTemplateWithCoinbases(context.Background(), requestData)
}

// GetNetworkState wraps the GetNetworkState RPC call
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetNetworkState instead.
func GetNetworkState() (*tari_generated.GetNetworkStateResponse, error) {
	client := tari_generated.NewBaseNodeClient(grpcConn)
	return client.GetNetworkState(context.Background(), nil)
}

// GetNewBlock wraps the GetNewBlock GRPC call
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetNewBlock instead.
func GetNewBlock(requestData *tari_generated.NewBlockTemplate) (*tari_generated.GetNewBlockResult, error) {
	client := tari_generated.NewBaseNodeClient(grpcConn)
	return client.GetNewBlock(context.Background(), requestData)
}

// GetBlockByHeight retrieves blocks, handles the streaming data, then returns the blocks as a slice
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetBlockByHeight instead.
func GetBlockByHeight(blockIDs []uint64) ([]*tari_generated.Block, error) {
	client := tari_generated.NewBaseNodeClient(grpcConn)
	active_client, err := client.GetBlocks(context.Background(), &tari_generated.GetBlocksRequest{Heights: blockIDs}, grpc.MaxCallRecvMsgSize(16*1024*1024))
	if err != nil {
		return nil, err
	}
	resp := make([]*tari_generated.Block, 0)
	for {
		blockResp, err := active_client.Recv()
		if err != nil {
			if err == io.EOF {
				return resp, nil
			}
			return nil, err
		}
		resp = append(resp, blockResp.GetBlock())
	}
}

// GetHeaderByHash wraps the GRPC call of the same name.
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetHeaderByHash instead.
func GetHeaderByHash(blockHash []byte) (*tari_generated.BlockHeaderResponse, error) {
	client := tari_generated.NewBaseNodeClient(grpcConn)
	return client.GetHeaderByHash(context.Background(), &tari_generated.GetHeaderByHashRequest{Hash: blockHash})
}

// SubmitBlock sends blocks to the daemon for processing
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).SubmitBlock instead.
func SubmitBlock(requestData *tari_generated.Block) (*tari_generated.SubmitBlockResponse, error) {
	client := tari_generated.NewBaseNodeClient(grpcConn)
	return client.SubmitBlock(context.Background(), requestData)
}

// GetNetworkDiff pulls the network diff of a given block, or it will just use tip if you give it a 0
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetNetworkDiff instead.
func GetNetworkDiff(height uint64) (*tari_generated.NetworkDifficultyResponse, error) {
	client := tari_generated.NewBaseNodeClient(grpcConn)
	var diffClient tari_generated.BaseNode_GetNetworkDifficultyClient
	var err error
	if height == 0 {
		diffClient, err = client.GetNetworkDifficulty(context.Background(), &tari_generated.HeightRequest{FromTip: 1})
	} else {
		diffClient, err = client.GetNetworkDifficulty(context.Background(), &tari_generated.HeightRequest{StartHeight: height, EndHeight: height})
	}
	if err != nil {
		return nil, err
	}
	return diffClient.Recv()
}

// GetNodeIdentity returns a list of valid rust identities for an opened GRPC node
//
// Deprecated: uses the unsafe package-level shared connection. Use (*Client).GetNodeIdentity instead.
func GetNodeIdentity() (*tari_generated.NodeIdentity, error) {
	client := tari_generated.NewBaseNodeClient(grpcConn)
	return client.Identify(context.Background(), nil)
}
