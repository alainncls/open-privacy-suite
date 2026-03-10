package explorer

import (
	"time"
)

type JSONString string

func (s JSONString) MarshalJSON() ([]byte, error) {
	return []byte(`"` + string(s) + `"`), nil
}

type Block struct {
	Number           uint64    `json:"number"`
	Hash             string    `json:"hash"`
	ParentHash       string    `json:"parentHash"`
	Timestamp        uint64    `json:"timestamp"`
	GasUsed          uint64    `json:"gasUsed"`
	GasLimit         uint64    `json:"gasLimit"`
	BaseFeePerGas    *uint64   `json:"baseFeePerGas,omitempty"`
	TransactionCount int       `json:"transactionCount"`
	Size             uint64    `json:"size"`
	Difficulty       string    `json:"difficulty"`
	TotalDifficulty  string    `json:"totalDifficulty"`
	Nonce            string    `json:"nonce"`
	Miner            string    `json:"miner"`
	ExtraData        string    `json:"extraData"`
	StateRoot        string    `json:"stateRoot"`
	TransactionsRoot string    `json:"transactionsRoot"`
	ReceiptsRoot     string    `json:"receiptsRoot"`
	CreatedAt        time.Time `json:"createdAt"`
}

type Transaction struct {
	Hash                 string     `json:"hash"`
	BlockNumber          uint64     `json:"blockNumber"`
	BlockTimestamp       uint64     `json:"blockTimestamp,omitempty"`
	TxIndex              int        `json:"txIndex"`
	From                 string     `json:"from"`
	To                   *string    `json:"to"`
	ContractAddress      *string    `json:"contractAddress,omitempty"`
	Value                JSONString `json:"value"`
	GasUsed              uint64     `json:"gasUsed"`
	GasPrice             uint64     `json:"gasPrice"`
	GasLimit             *uint64    `json:"gasLimit,omitempty"`
	MaxFeePerGas         *uint64    `json:"maxFeePerGas,omitempty"`
	MaxPriorityFeePerGas *uint64    `json:"maxPriorityFeePerGas,omitempty"`
	Nonce                *uint64    `json:"nonce,omitempty"`
	TxType               int        `json:"txType"`
	InputData            string     `json:"inputData"`
	Status               int        `json:"status"`
	Error                *string    `json:"error,omitempty"`
	RevertReason         *string    `json:"revertReason,omitempty"`
	CreatedAt            time.Time  `json:"createdAt"`
	TxCategories         []string   `json:"txCategories,omitempty"`
	TokenTransferCount   int        `json:"tokenTransferCount,omitempty"`
}

type AddressStats struct {
	Address            string    `json:"address"`
	TxCount            int       `json:"txCount"`
	InternalTxCount    int       `json:"internalTxCount"`
	TokenTransferCount int       `json:"tokenTransferCount"`
	FirstSeen          *uint64   `json:"firstSeen"`
	LastSeen           *uint64   `json:"lastSeen"`
	IsContract         bool      `json:"isContract"`
	UpdatedAt          time.Time `json:"updatedAt"`
}

type TokenTransfer struct {
	ID           int64      `json:"id"`
	TxHash       string     `json:"txHash"`
	LogIndex     int        `json:"logIndex"`
	TokenAddress string     `json:"tokenAddress"`
	From         string     `json:"from"`
	To           string     `json:"to"`
	Value        JSONString `json:"value"`
	BlockNumber  uint64     `json:"blockNumber"`
	Timestamp    *uint64    `json:"timestamp,omitempty"`
	TransferType string     `json:"transferType"`
	TokenType    string     `json:"tokenType"`
	TokenID      *string    `json:"tokenId,omitempty"`
	IsInternal   bool       `json:"isInternal"`
}

type InternalTransaction struct {
	ID           int64      `json:"id"`
	TxHash       string     `json:"txHash"`
	BlockNumber  uint64     `json:"blockNumber"`
	TraceAddress string     `json:"traceAddress"`
	From         string     `json:"from"`
	To           *string    `json:"to"`
	Value        JSONString `json:"value"`
	Gas          *uint64    `json:"gas,omitempty"`
	GasUsed      *uint64    `json:"gasUsed,omitempty"`
	Input        *string    `json:"input,omitempty"`
	Output       *string    `json:"output,omitempty"`
	CallType     string     `json:"callType"`
	Error        *string    `json:"error,omitempty"`
	Timestamp    *uint64    `json:"timestamp,omitempty"`
}

type Log struct {
	ID          int64   `json:"id"`
	TxHash      string  `json:"txHash"`
	LogIndex    int     `json:"logIndex"`
	Address     string  `json:"address"`
	Topic0      *string `json:"topic0"`
	Topic1      *string `json:"topic1"`
	Topic2      *string `json:"topic2"`
	Topic3      *string `json:"topic3"`
	Data        string  `json:"data"`
	BlockNumber uint64  `json:"blockNumber"`
	Timestamp   *uint64 `json:"timestamp,omitempty"`
	Removed     bool    `json:"removed"`
}

type SyncStatus struct {
	LastIndexedBlock uint64    `json:"lastIndexedBlock"`
	IsSyncing        bool      `json:"isSyncing"`
	UpdatedAt        time.Time `json:"updatedAt"`
}

type ChainStats struct {
	BlockCount       uint64 `json:"blockCount"`
	TransactionCount uint64 `json:"transactionCount"`
	AddressCount     uint64 `json:"addressCount"`
}
