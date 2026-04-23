package explorer

import (
	"context"
	"encoding/json"
)

// ExplorerBackend is the abstract surface the explorer API handlers and
// RedactionEngine use to read chain data. Both *Store (direct SQL to the
// explorer postgres, legacy) and the gRPC indexer client satisfy it.
//
// Introduced for RD-855 Phase 3: we migrate callers off direct SQL onto the
// chain-indexer gRPC API, one method at a time. The gRPC-backed
// implementation embeds *Store so that unmigrated methods still hit the
// existing SQL path until they're ported.
//
// Method set is the public surface of *Store. Keep this interface in sync
// when *Store gains new methods; the Go compiler will enforce both
// implementations still satisfy it.
type ExplorerBackend interface {
	Close() error

	// Chain stats
	GetChainStats(ctx context.Context) (*ChainStats, error)
	GetChainStatsFiltered(ctx context.Context, filter *VisibilityFilter) (*ChainStats, error)
	GetTransactionHistory(ctx context.Context, intervalSeconds int, limit int) ([]TxHistoryPoint, error)
	GetTransactionHistoryFiltered(ctx context.Context, intervalSeconds int, limit int, filter *VisibilityFilter) ([]TxHistoryPoint, error)

	// Blocks
	GetBlock(ctx context.Context, number uint64) (*Block, error)
	GetBlockByHash(ctx context.Context, hash string) (*Block, error)
	GetBlocks(ctx context.Context, limit int, beforeBlock *uint64) ([]Block, error)
	GetBlocksFiltered(ctx context.Context, limit int, beforeBlock *uint64, filter *VisibilityFilter) ([]Block, error)
	GetBlockTransactionCountFiltered(ctx context.Context, blockNumber uint64, filter *VisibilityFilter) (int, error)
	GetLatestBlockNumber(ctx context.Context) (uint64, error)

	// Transactions
	GetTransaction(ctx context.Context, hash string) (*Transaction, error)
	GetTransactionWithCategories(ctx context.Context, hash string) (*Transaction, error)
	GetTransactions(ctx context.Context, limit int, beforeBlock *uint64) ([]Transaction, error)
	GetTransactionsByAddress(ctx context.Context, address string, limit int, beforeBlock *uint64) ([]Transaction, error)
	GetTransactionsByBlock(ctx context.Context, blockNumber uint64) ([]Transaction, error)
	GetTransactionsPaginated(ctx context.Context, page, pageSize int) ([]Transaction, int64, error)
	GetTransactionsWithCategories(ctx context.Context, limit int, beforeBlock *uint64) ([]Transaction, error)
	GetTransactionsPaginatedWithCategories(ctx context.Context, page, pageSize int) ([]Transaction, int64, error)
	GetTransactionsFiltered(ctx context.Context, limit int, beforeBlock *uint64, filter *VisibilityFilter) ([]Transaction, error)
	GetTransactionsPaginatedFiltered(ctx context.Context, page, pageSize int, filter *VisibilityFilter) ([]Transaction, int64, error)
	GetTransactionsWithCategoriesFiltered(ctx context.Context, limit int, beforeBlock *uint64, filter *VisibilityFilter) ([]Transaction, error)
	GetTransactionsPaginatedWithCategoriesFiltered(ctx context.Context, page, pageSize int, filter *VisibilityFilter) ([]Transaction, int64, error)

	// Addresses
	GetAddressStats(ctx context.Context, address string) (*AddressStats, error)
	GetAddressTransactionCountFiltered(ctx context.Context, address string, filter *VisibilityFilter) (int, error)
	GetAccountsPaginated(ctx context.Context, page, pageSize int) ([]AddressStats, int64, error)

	// Transfers
	GetTransfersByTransaction(ctx context.Context, txHash string) ([]TokenTransfer, error)
	GetTransfersByAddress(ctx context.Context, address string, limit int, beforeBlock *uint64) ([]TokenTransfer, error)
	GetTransfersByToken(ctx context.Context, tokenAddress string, limit int, offset int) ([]TokenTransfer, int64, error)
	GetAllTransfers(ctx context.Context, limit int, offset int) ([]TokenTransfer, int64, error)

	// Logs
	GetLogsByTransaction(ctx context.Context, txHash string) ([]Log, error)
	GetLogsByAddress(ctx context.Context, address string, limit int, offset int) ([]Log, int64, error)
	GetLogs(ctx context.Context, address *string, topic0 *string, fromBlock *uint64, toBlock *uint64, limit int) ([]Log, error)

	// Internal transactions
	GetInternalTransactionsByTx(ctx context.Context, txHash string) ([]InternalTransaction, error)
	GetInternalTransactionsByAddress(ctx context.Context, address string, limit int, offset int) ([]InternalTransaction, int64, error)
	GetInternalTransactionsByBlock(ctx context.Context, blockNumber uint64) ([]InternalTransaction, error)

	// Contracts
	GetContract(ctx context.Context, address string) (*Contract, error)
	IsContract(ctx context.Context, address string) (bool, error)
	SetContractABI(ctx context.Context, address string, abi json.RawMessage) error

	// Tokens
	GetToken(ctx context.Context, address string) (*Token, error)
	GetTokens(ctx context.Context, limit int, offset int, tokenType string) ([]Token, int64, error)
	GetTokenHolders(ctx context.Context, address string, limit int, offset int) ([]TokenHolder, int64, error)
	GetTokenBalances(ctx context.Context, address string) ([]Balance, error)

	// Sync status
	GetSyncStatus(ctx context.Context) (*SyncStatus, error)
	GetIndexerProgress(ctx context.Context) (*IndexerProgress, error)

	// Search
	SearchSuggestions(ctx context.Context, query string, limit int) ([]SearchSuggestion, error)
}

// Compile-time assertion that *Store satisfies ExplorerBackend.
var _ ExplorerBackend = (*Store)(nil)
