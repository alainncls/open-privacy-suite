package explorer

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type Store struct {
	db *sql.DB
}

func NewStore(databaseURL string) (*Store, error) {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return nil, fmt.Errorf("failed to open explorer database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping explorer database: %w", err)
	}

	return &Store{db: db}, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

// Chain Stats oeprations

func (s *Store) GetChainStats(ctx context.Context) (*ChainStats, error) {
	var stats ChainStats
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM blocks").Scan(&stats.BlockCount)
	if err != nil {
		return nil, err
	}
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM transactions").Scan(&stats.TransactionCount)
	if err != nil {
		return nil, err
	}
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM address_stats").Scan(&stats.AddressCount)
	if err != nil {
		return nil, err
	}
	return &stats, nil
}

// Block operations

func (s *Store) GetBlock(ctx context.Context, number uint64) (*Block, error) {
	var b Block
	err := s.db.QueryRowContext(ctx, `
		SELECT number, hash, parent_hash, timestamp, gas_used, gas_limit, base_fee_per_gas, transaction_count,
			size, difficulty, total_difficulty, nonce, miner, extra_data, state_root, transactions_root, receipts_root, created_at
		FROM blocks WHERE number = $1`, number).Scan(
		&b.Number, &b.Hash, &b.ParentHash, &b.Timestamp, &b.GasUsed, &b.GasLimit, &b.BaseFeePerGas, &b.TransactionCount,
		&b.Size, &b.Difficulty, &b.TotalDifficulty, &b.Nonce, &b.Miner, &b.ExtraData, &b.StateRoot, &b.TransactionsRoot, &b.ReceiptsRoot, &b.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &b, err
}

func (s *Store) GetBlockByHash(ctx context.Context, hash string) (*Block, error) {
	var b Block
	err := s.db.QueryRowContext(ctx, `
		SELECT number, hash, parent_hash, timestamp, gas_used, gas_limit, base_fee_per_gas, transaction_count,
			size, difficulty, total_difficulty, nonce, miner, extra_data, state_root, transactions_root, receipts_root, created_at
		FROM blocks WHERE hash = $1`, hash).Scan(
		&b.Number, &b.Hash, &b.ParentHash, &b.Timestamp, &b.GasUsed, &b.GasLimit, &b.BaseFeePerGas, &b.TransactionCount,
		&b.Size, &b.Difficulty, &b.TotalDifficulty, &b.Nonce, &b.Miner, &b.ExtraData, &b.StateRoot, &b.TransactionsRoot, &b.ReceiptsRoot, &b.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &b, err
}

func (s *Store) GetBlocks(ctx context.Context, limit int, beforeBlock *uint64) ([]Block, error) {
	var rows *sql.Rows
	var err error

	if beforeBlock != nil {
		rows, err = s.db.QueryContext(ctx, `
			SELECT number, hash, parent_hash, timestamp, gas_used, gas_limit, base_fee_per_gas, transaction_count,
				size, difficulty, total_difficulty, nonce, miner, extra_data, state_root, transactions_root, receipts_root, created_at
			FROM blocks WHERE number < $1 ORDER BY number DESC LIMIT $2`, *beforeBlock, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT number, hash, parent_hash, timestamp, gas_used, gas_limit, base_fee_per_gas, transaction_count,
				size, difficulty, total_difficulty, nonce, miner, extra_data, state_root, transactions_root, receipts_root, created_at
			FROM blocks ORDER BY number DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var blocks []Block
	for rows.Next() {
		var b Block
		if err := rows.Scan(&b.Number, &b.Hash, &b.ParentHash, &b.Timestamp, &b.GasUsed, &b.GasLimit, &b.BaseFeePerGas, &b.TransactionCount,
			&b.Size, &b.Difficulty, &b.TotalDifficulty, &b.Nonce, &b.Miner, &b.ExtraData, &b.StateRoot, &b.TransactionsRoot, &b.ReceiptsRoot, &b.CreatedAt); err != nil {
			return nil, err
		}
		blocks = append(blocks, b)
	}
	return blocks, rows.Err()
}

// Transaction operations

func (s *Store) GetTransaction(ctx context.Context, hash string) (*Transaction, error) {
	var tx Transaction
	var valueStr string
	err := s.db.QueryRowContext(ctx, `
		SELECT t.hash, t.block_number, t.tx_index, t.from_address, t.to_address, t.value::text,
			t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
			t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
		FROM transactions t
		WHERE t.hash = $1`, hash).Scan(
		&tx.Hash, &tx.BlockNumber, &tx.TxIndex, &tx.From, &tx.To, &valueStr,
		&tx.GasUsed, &tx.GasPrice, &tx.GasLimit, &tx.MaxFeePerGas, &tx.MaxPriorityFeePerGas, &tx.Nonce,
		&tx.TxType, &tx.InputData, &tx.Status, &tx.Error, &tx.RevertReason, &tx.CreatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	tx.Value = JSONString(valueStr)
	return &tx, nil
}

func (s *Store) GetTransactions(ctx context.Context, limit int, beforeBlock *uint64) ([]Transaction, error) {
	var rows *sql.Rows
	var err error

	if beforeBlock != nil {
		rows, err = s.db.QueryContext(ctx, `
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE t.block_number < $1 ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $2`, *beforeBlock, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $1`, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	return s.scanTransactions(rows)
}

func (s *Store) GetTransactionsByAddress(ctx context.Context, address string, limit int, beforeBlock *uint64) ([]Transaction, error) {
	address = strings.ToLower(address)
	var rows *sql.Rows
	var err error

	if beforeBlock != nil {
		rows, err = s.db.QueryContext(ctx, `
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE (LOWER(t.from_address) = $1 OR LOWER(t.to_address) = $1) AND t.block_number < $2
			ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $3`, address, *beforeBlock, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, `
			SELECT t.hash, t.block_number, b.timestamp, t.tx_index, t.from_address, t.to_address, t.value::text,
				t.gas_used, t.gas_price, t.gas_limit, t.max_fee_per_gas, t.max_priority_fee_per_gas, t.nonce,
				t.tx_type, t.input_data, t.status, t.error, t.revert_reason, t.created_at
			FROM transactions t
			JOIN blocks b ON t.block_number = b.number
			WHERE LOWER(t.from_address) = $1 OR LOWER(t.to_address) = $1
			ORDER BY t.block_number DESC, t.tx_index DESC LIMIT $2`, address, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return s.scanTransactions(rows)
}

func (s *Store) scanTransactions(rows *sql.Rows) ([]Transaction, error) {
	var txs []Transaction
	for rows.Next() {
		var tx Transaction
		var valueStr string
		if err := rows.Scan(&tx.Hash, &tx.BlockNumber, &tx.BlockTimestamp, &tx.TxIndex, &tx.From, &tx.To, &valueStr,
			&tx.GasUsed, &tx.GasPrice, &tx.GasLimit, &tx.MaxFeePerGas, &tx.MaxPriorityFeePerGas, &tx.Nonce,
			&tx.TxType, &tx.InputData, &tx.Status, &tx.Error, &tx.RevertReason, &tx.CreatedAt); err != nil {
			return nil, err
		}
		tx.Value = JSONString(valueStr)
		txs = append(txs, tx)
	}
	return txs, rows.Err()
}

// Sync Status

func (s *Store) GetSyncStatus(ctx context.Context) (*SyncStatus, error) {
	var ss SyncStatus
	err := s.db.QueryRowContext(ctx, `
		SELECT last_indexed_block, is_syncing, updated_at
		FROM sync_status ORDER BY id DESC LIMIT 1`).Scan(
		&ss.LastIndexedBlock, &ss.IsSyncing, &ss.UpdatedAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return &ss, err
}

func (s *Store) GetAddressStats(ctx context.Context, address string) (*AddressStats, error) {
	address = strings.ToLower(address)
	var stats AddressStats
	err := s.db.QueryRowContext(ctx, `
		SELECT address, tx_count, internal_tx_count, token_transfer_count, first_seen, last_seen, is_contract, updated_at
		FROM address_stats WHERE LOWER(address) = $1`, address).Scan(
		&stats.Address, &stats.TxCount, &stats.InternalTxCount, &stats.TokenTransferCount, &stats.FirstSeen, &stats.LastSeen, &stats.IsContract, &stats.UpdatedAt)
	if err == sql.ErrNoRows {
		// Return empty stats if not found
		return &AddressStats{Address: address}, nil
	}
	return &stats, err
}

// Internal Transactions

func (s *Store) GetInternalTransactionsByTx(ctx context.Context, txHash string) ([]InternalTransaction, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tx_hash, block_number, trace_address, from_address, to_address, value::text,
			gas, gas_used, input, output, call_type, error, timestamp
		FROM internal_transactions WHERE tx_hash = $1 ORDER BY id`, txHash)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var txs []InternalTransaction
	for rows.Next() {
		var tx InternalTransaction
		var valueStr string
		if err := rows.Scan(&tx.ID, &tx.TxHash, &tx.BlockNumber, &tx.TraceAddress, &tx.From, &tx.To, &valueStr,
			&tx.Gas, &tx.GasUsed, &tx.Input, &tx.Output, &tx.CallType, &tx.Error, &tx.Timestamp); err != nil {
			return nil, err
		}
		tx.Value = JSONString(valueStr)
		txs = append(txs, tx)
	}
	return txs, rows.Err()
}
