package indexerclient

import (
	"strconv"

	indexerv1 "github.com/gateway-fm/chain-indexer/gen/go/chain_indexer/v1"
	"privacy-proxy/internal/explorer"
)

// Type conversion helpers from chain-indexer proto messages to privacy-proxy's
// internal explorer.* types. Kept narrow and field-by-field so breakage is
// explicit when the proto changes.

func unixSec(t interface{ GetSeconds() int64 }) uint64 {
	if t == nil {
		return 0
	}
	s := t.GetSeconds()
	if s < 0 {
		return 0
	}
	return uint64(s)
}

// big converts a proto BigInt to a string ("" if unset or zero-value).
func big(b *indexerv1.BigInt) string {
	if b == nil {
		return ""
	}
	return b.GetValue()
}

// bigToUint64Ptr parses a decimal BigInt into *uint64. Returns nil if empty
// or unparseable. Used for fields that the privacy-proxy store historically
// scanned as *uint64 directly from postgres.
func bigToUint64Ptr(b *indexerv1.BigInt) *uint64 {
	if b == nil || b.GetValue() == "" {
		return nil
	}
	n, err := strconv.ParseUint(b.GetValue(), 10, 64)
	if err != nil {
		return nil
	}
	return &n
}

func bigToUint64(b *indexerv1.BigInt) uint64 {
	if b == nil || b.GetValue() == "" {
		return 0
	}
	n, err := strconv.ParseUint(b.GetValue(), 10, 64)
	if err != nil {
		return 0
	}
	return n
}

func mapBlock(b *indexerv1.Block) *explorer.Block {
	if b == nil {
		return nil
	}
	baseFee := bigToUint64Ptr(b.GetBaseFeePerGas())
	return &explorer.Block{
		Number:           b.GetNumber(),
		Hash:             b.GetHash(),
		ParentHash:       b.GetParentHash(),
		Timestamp:        unixSec(b.GetTimestamp()),
		GasUsed:          b.GetGasUsed(),
		GasLimit:         b.GetGasLimit(),
		BaseFeePerGas:    baseFee,
		TransactionCount: int(b.GetTransactionCount()),
		Size:             b.GetSize(),
		Difficulty:       big(b.GetDifficulty()),
		TotalDifficulty:  big(b.GetTotalDifficulty()),
		Nonce:            b.GetNonce(),
		Miner:            b.GetMiner(),
		ExtraData:        b.GetExtraData(),
		StateRoot:        b.GetStateRoot(),
		TransactionsRoot: b.GetTransactionsRoot(),
		ReceiptsRoot:     b.GetReceiptsRoot(),
		// CreatedAt is a DB-local timestamp, not carried over gRPC.
	}
}

// mapCategory translates a proto TransactionCategory enum to the string label
// that privacy-proxy's existing code (and tests) expects.
func mapCategory(c indexerv1.TransactionCategory) string {
	switch c {
	case indexerv1.TransactionCategory_TRANSACTION_CATEGORY_COIN_TRANSFER:
		return "coin_transfer"
	case indexerv1.TransactionCategory_TRANSACTION_CATEGORY_CONTRACT_CREATION:
		return "contract_creation"
	case indexerv1.TransactionCategory_TRANSACTION_CATEGORY_CONTRACT_CALL:
		return "contract_call"
	case indexerv1.TransactionCategory_TRANSACTION_CATEGORY_TOKEN_TRANSFER:
		return "token_transfer"
	}
	return ""
}

func mapCategories(cs []indexerv1.TransactionCategory) []string {
	if len(cs) == 0 {
		return nil
	}
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		if label := mapCategory(c); label != "" {
			out = append(out, label)
		}
	}
	return out
}

func mapStatus(s indexerv1.TransactionStatus) int {
	switch s {
	case indexerv1.TransactionStatus_TRANSACTION_STATUS_SUCCESS:
		return 1
	case indexerv1.TransactionStatus_TRANSACTION_STATUS_FAILED:
		return 0
	}
	return 0
}

func stringPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func mapTransaction(t *indexerv1.Transaction) *explorer.Transaction {
	if t == nil {
		return nil
	}
	var to *string
	if t.GetTo() != "" {
		to = stringPtr(t.GetTo())
	}
	var contractAddr *string
	if t.GetContractAddress() != "" {
		contractAddr = stringPtr(t.GetContractAddress())
	}
	gasLimit := t.GetGas()
	nonce := t.GetNonce()
	return &explorer.Transaction{
		Hash:                 t.GetHash(),
		BlockNumber:          t.GetBlockNumber(),
		BlockTimestamp:       unixSec(t.GetBlockTimestamp()),
		TxIndex:              int(t.GetTransactionIndex()),
		From:                 t.GetFrom(),
		To:                   to,
		ContractAddress:      contractAddr,
		Value:                explorer.JSONString(big(t.GetValue())),
		GasUsed:              t.GetGasUsed(),
		GasPrice:             bigToUint64(t.GetGasPrice()),
		GasLimit:             &gasLimit,
		MaxFeePerGas:         bigToUint64Ptr(t.GetMaxFeePerGas()),
		MaxPriorityFeePerGas: bigToUint64Ptr(t.GetMaxPriorityFeePerGas()),
		Nonce:                &nonce,
		TxType:               int(t.GetTxType()),
		InputData:            t.GetInput(),
		Status:               mapStatus(t.GetStatus()),
		TxCategories:         mapCategories(t.GetCategories()),
	}
}

func mapAddressStats(a *indexerv1.Address) *explorer.AddressStats {
	if a == nil {
		return nil
	}
	first := a.GetFirstSeenBlock()
	last := a.GetLastSeenBlock()
	return &explorer.AddressStats{
		Address:            a.GetAddress(),
		TxCount:            int(a.GetTxCountIn() + a.GetTxCountOut()),
		InternalTxCount:    0, // chain-indexer collapses this into proto Address.TxCount*; not exposed separately
		TokenTransferCount: int(a.GetTokenCount()),
		FirstSeen:          &first,
		LastSeen:           &last,
		IsContract:         a.GetIsContract(),
	}
}

func mapChainStats(c *indexerv1.ChainStats) *explorer.ChainStats {
	if c == nil {
		return nil
	}
	return &explorer.ChainStats{
		TotalBlocks:       int64(c.GetTotalBlocks()),
		TotalTransactions: int64(c.GetTotalTransactions()),
		TotalAddresses:    int64(c.GetTotalAddresses()),
		TotalTokens:       0, // not exposed separately by the indexer today
		AvgBlockTime:      float64(c.GetAvgBlockTimeSeconds()),
		PrivacyEnabled:    true,
	}
}

func mapSyncStatus(s *indexerv1.SyncStatus) *explorer.SyncStatus {
	if s == nil {
		return nil
	}
	return &explorer.SyncStatus{
		LastIndexedBlock: s.GetLatestIndexedBlock(),
		IsSyncing:        s.GetIsSyncing(),
	}
}
