package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func registerExplorerTools(s *mcp.Server, client *httpClient) {
	registerExplorerSyncStatus(s, client)
	registerExplorerBlocks(s, client)
	registerExplorerBlock(s, client)
	registerExplorerTransactions(s, client)
	registerExplorerTransaction(s, client)
	registerExplorerAddress(s, client)
	registerExplorerAddressTxs(s, client)
	registerExplorerAddressBalance(s, client)
	registerExplorerTokens(s, client)
	registerViewableAddresses(s, client)
	registerCheckAddressVisibility(s, client)
}

func registerExplorerSyncStatus(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_sync_status",
		Description: "Get block explorer indexer sync status and progress.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, any, error) {
		raw, err := client.get("/api/v1/explorer/sync/status")
		if err != nil {
			return errorResult("getting sync status: %v", err)
		}
		return textResult(section("Explorer Sync Status"), prettyJSON(json.RawMessage(raw)))
	})
}

type explorerListArgs struct {
	Limit  int `json:"limit,omitempty" jsonschema:"max entries (default 20)"`
	Offset int `json:"offset,omitempty" jsonschema:"pagination offset"`
}

func registerExplorerBlocks(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_blocks",
		Description: "List recent blocks from the explorer.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args explorerListArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit == 0 {
			limit = 20
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/explorer/blocks?limit=%d&offset=%d", limit, args.Offset))
		if err != nil {
			return errorResult("listing blocks: %v", err)
		}
		var blocks []any
		if err := json.Unmarshal(raw, &blocks); err != nil {
			return errorResult("parsing response: %v", err)
		}

		lines := section("Blocks") + "\n"
		for _, b := range blocks {
			block, ok := b.(map[string]any)
			if !ok {
				continue
			}
			lines += fmt.Sprintf("Block %-8.0f | %s | %.0f txs\n",
				getFloat(block, "number"),
				getString(block, "timestamp"),
				getFloat(block, "transaction_count"),
			)
		}

		return textResult(lines)
	})
}

type blockArgs struct {
	Number string `json:"number" jsonschema:"block number or 'latest' (required)"`
}

func registerExplorerBlock(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_block",
		Description: "Get details of a specific block by number.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args blockArgs) (*mcp.CallToolResult, any, error) {
		if args.Number == "" {
			return errorResult("number is required")
		}
		raw, err := client.get("/api/v1/explorer/blocks/" + url.PathEscape(args.Number))
		if err != nil {
			return errorResult("getting block: %v", err)
		}
		return textResult(section("Block "+args.Number), prettyJSON(json.RawMessage(raw)))
	})
}

func registerExplorerTransactions(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_transactions",
		Description: "List recent transactions from the explorer.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args explorerListArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit == 0 {
			limit = 20
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/explorer/transactions?limit=%d&offset=%d", limit, args.Offset))
		if err != nil {
			return errorResult("listing transactions: %v", err)
		}
		var txs []any
		if err := json.Unmarshal(raw, &txs); err != nil {
			return errorResult("parsing response: %v", err)
		}

		lines := section("Transactions") + "\n"
		for i, t := range txs {
			if i >= 20 {
				lines += fmt.Sprintf("\n... and %d more", len(txs)-20)
				break
			}
			tx, ok := t.(map[string]any)
			if !ok {
				continue
			}
			lines += fmt.Sprintf("%s → %s (%.0f)\n",
				getString(tx, "from"),
				getString(tx, "to"),
				getFloat(tx, "value"),
			)
		}

		return textResult(lines)
	})
}

type txHashArgs struct {
	Hash string `json:"hash" jsonschema:"transaction hash (0x-prefixed, required)"`
}

func registerExplorerTransaction(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_transaction",
		Description: "Get details of a specific transaction by hash.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args txHashArgs) (*mcp.CallToolResult, any, error) {
		if args.Hash == "" {
			return errorResult("hash is required")
		}
		raw, err := client.get("/api/v1/explorer/transactions/" + url.PathEscape(args.Hash))
		if err != nil {
			return errorResult("getting transaction: %v", err)
		}
		return textResult(section("Transaction"), prettyJSON(json.RawMessage(raw)))
	})
}

type addressArgs struct {
	Address string `json:"address" jsonschema:"ETH address (0x-prefixed, required)"`
}

func registerExplorerAddress(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_address",
		Description: "Get address statistics: transaction count, balance, contract info.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args addressArgs) (*mcp.CallToolResult, any, error) {
		if args.Address == "" {
			return errorResult("address is required")
		}
		raw, err := client.get("/api/v1/explorer/addresses/" + url.PathEscape(args.Address) + "/stats")
		if err != nil {
			return errorResult("getting address stats: %v", err)
		}
		return textResult(section("Address: "+args.Address), prettyJSON(json.RawMessage(raw)))
	})
}

type addressTxsArgs struct {
	Address string `json:"address" jsonschema:"ETH address (0x-prefixed, required)"`
	Limit   int    `json:"limit,omitempty" jsonschema:"max entries (default 20)"`
	Offset  int    `json:"offset,omitempty" jsonschema:"pagination offset"`
}

func registerExplorerAddressTxs(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_address_transactions",
		Description: "Get transactions for a specific address.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args addressTxsArgs) (*mcp.CallToolResult, any, error) {
		if args.Address == "" {
			return errorResult("address is required")
		}
		limit := args.Limit
		if limit == 0 {
			limit = 20
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/explorer/addresses/%s/transactions?limit=%d&offset=%d", url.PathEscape(args.Address), limit, args.Offset))
		if err != nil {
			return errorResult("getting address transactions: %v", err)
		}
		return textResult(section("Transactions for "+args.Address), prettyJSON(json.RawMessage(raw)))
	})
}

func registerExplorerAddressBalance(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_address_balance",
		Description: "Get ETH balance for an address.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args addressArgs) (*mcp.CallToolResult, any, error) {
		if args.Address == "" {
			return errorResult("address is required")
		}
		raw, err := client.get("/api/v1/explorer/addresses/" + url.PathEscape(args.Address) + "/balance")
		if err != nil {
			return errorResult("getting balance: %v", err)
		}
		return textResult(section("Balance: "+args.Address), prettyJSON(json.RawMessage(raw)))
	})
}

func registerExplorerTokens(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "explorer_tokens",
		Description: "List tokens indexed by the explorer.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args explorerListArgs) (*mcp.CallToolResult, any, error) {
		limit := args.Limit
		if limit == 0 {
			limit = 20
		}
		raw, err := client.get(fmt.Sprintf("/api/v1/explorer/tokens?limit=%d&offset=%d", limit, args.Offset))
		if err != nil {
			return errorResult("listing tokens: %v", err)
		}
		return textResult(section("Tokens"), prettyJSON(json.RawMessage(raw)))
	})
}

type viewableAddressesArgs struct {
	Wallet string `json:"wallet" jsonschema:"ETH wallet address to check visibility for (required)"`
}

func registerViewableAddresses(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "viewable_addresses",
		Description: "Get all addresses a wallet can see (own + disclosed via grants). Wallet address is required.",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args viewableAddressesArgs) (*mcp.CallToolResult, any, error) {
		wallet := args.Wallet
		if wallet == "" {
			return errorResult("wallet address required")
		}

		raw, err := client.get("/api/v1/explorer/viewable-addresses?wallet=" + url.QueryEscape(wallet))
		if err != nil {
			return errorResult("getting viewable addresses: %v", err)
		}
		lines := section("Viewable Addresses for " + wallet)

		return textResult(lines, prettyJSON(json.RawMessage(raw)))
	})
}

type checkVisibilityArgs struct {
	Address string `json:"address" jsonschema:"ETH address to check (0x-prefixed, required)"`
}

func registerCheckAddressVisibility(s *mcp.Server, client *httpClient) {
	mcp.AddTool(s, &mcp.Tool{
		Name:        "check_address_visibility",
		Description: "Check if a specific address is visible to a viewer (requires wallet query param or JWT on the API side).",
	}, func(ctx context.Context, req *mcp.CallToolRequest, args checkVisibilityArgs) (*mcp.CallToolResult, any, error) {
		if args.Address == "" {
			return errorResult("address is required")
		}
		raw, err := client.get("/api/v1/explorer/check-address/" + args.Address)
		if err != nil {
			return errorResult("checking address visibility: %v", err)
		}
		lines := section("Address Visibility: " + args.Address)

		return textResult(lines, prettyJSON(json.RawMessage(raw)))
	})
}
