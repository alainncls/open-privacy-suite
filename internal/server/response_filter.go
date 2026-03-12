package server

// TODO: Multi-party event stakeholder whitelists
// Events using a business identifier (e.g., paymentIdentifier) instead of address parameters
// require a per-event-ID stakeholder whitelist (e.g., debtor bank, settlement bank, creditor
// bank for a PaymentInitiated event). This needs a new data model and admin API.
// Until then, events without indexed address parameters are filtered out for all users.
//
// TODO: eth_call response ABI decoding
// The response to eth_call is raw ABI-encoded bytes. For full field-level privacy
// (e.g., hiding the 'amount' field in getPaymentInfo unless user is a party),
// the proxy would need to decode the ABI response and selectively redact fields.
// This requires the contract ABI to be registered and per-function redaction rules.
//
// TODO: Traffic analysis via block metadata
// eth_getBlockTransactionCountByHash/Number reveal how many transactions are in a block,
// which enables coarse traffic analysis even without calldata access.

import (
	"bytes"
	"encoding/json"
	"strings"
)

// rpcResponseID extracts the raw "id" field from a JSON-RPC response body.
// Returns "null" if not found.
func rpcResponseID(body []byte) string {
	var envelope struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(body, &envelope) == nil && envelope.ID != nil {
		return string(envelope.ID)
	}
	return "null"
}

// addrSetFromLinked builds a lowercase address set for O(1) lookup.
func addrSetFromLinked(addrs []string) map[string]bool {
	set := make(map[string]bool, len(addrs))
	for _, a := range addrs {
		set[strings.ToLower(a)] = true
	}
	return set
}

// topicMatchesAddress checks if a 32-byte topic hex string encodes one of the
// user's linked addresses (topic = 0x + 24 zero chars + 40 hex addr chars).
func topicMatchesAddress(topic string, addrSet map[string]bool) bool {
	topic = strings.ToLower(topic)
	// Topics are 66 chars: "0x" + 64 hex. Address is the last 40 chars.
	if len(topic) == 66 && strings.HasPrefix(topic, "0x") {
		// Prefix must be all zeros (address padding)
		prefix := topic[2:26] // 24 chars of padding
		if strings.Trim(prefix, "0") == "" {
			addr := "0x" + topic[26:]
			return addrSet[addr]
		}
	}
	return false
}

// FilterTransactionByHash filters an eth_getTransactionByHash response.
// Returns null result if the user (identified by their linked ETH addresses)
// is not the sender (from) or recipient (to) of the transaction.
// If the transaction result is already null, passes through unchanged.
func FilterTransactionByHash(responseBody []byte, userAddresses []string) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return responseBody // parse error: pass through
	}
	// Pass through errors and null results unchanged
	if resp.Error != nil || resp.Result == nil {
		return responseBody
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return responseBody
	}

	var tx struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := json.Unmarshal(raw, &tx); err != nil {
		return responseBody
	}

	addrSet := addrSetFromLinked(userAddresses)
	from := strings.ToLower(tx.From)
	to := strings.ToLower(tx.To)

	if addrSet[from] || (to != "" && addrSet[to]) {
		return responseBody // participant -- return full response
	}

	// Not a participant -- return null
	id := rpcResponseID(responseBody)
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":null}`)
}

// FilterTransactionReceipt filters an eth_getTransactionReceipt response.
// For non-participants: returns a receipt with empty logs and zeroed logsBloom.
// If result is null, passes through unchanged.
func FilterTransactionReceipt(responseBody []byte, userAddresses []string) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return responseBody
	}
	if resp.Error != nil || resp.Result == nil {
		return responseBody
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return responseBody
	}

	var receipt struct {
		From string `json:"from"`
		To   string `json:"to"`
	}
	if err := json.Unmarshal(raw, &receipt); err != nil {
		return responseBody
	}

	addrSet := addrSetFromLinked(userAddresses)
	from := strings.ToLower(receipt.From)
	to := strings.ToLower(receipt.To)

	if addrSet[from] || (to != "" && addrSet[to]) {
		return responseBody // participant -- return full receipt
	}

	// Non-participant: return null result (consistent with FilterTransactionByHash).
	id := rpcResponseID(responseBody)
	return []byte(`{"jsonrpc":"2.0","id":` + id + `,"result":null}`)
}

// FilterLogs filters an eth_getLogs response, keeping only log entries where
// at least one indexed topic (topics[1+]) encodes one of the user's linked
// Ethereum addresses. Logs with no address-indexed topics are removed.
// If the result is not a JSON array or is null, passes through unchanged.
func FilterLogs(responseBody []byte, userAddresses []string) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return responseBody
	}
	if resp.Error != nil || resp.Result == nil {
		return responseBody
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return responseBody
	}

	// Parse as array of raw messages for round-trip fidelity
	var rawLogs []json.RawMessage
	if err := json.Unmarshal(raw, &rawLogs); err != nil {
		return responseBody // not an array -- pass through
	}

	addrSet := addrSetFromLinked(userAddresses)

	filtered := make([]json.RawMessage, 0, len(rawLogs))
	for _, rawLog := range rawLogs {
		var entry struct {
			Topics []string `json:"topics"`
		}
		if err := json.Unmarshal(rawLog, &entry); err != nil {
			continue // skip malformed entries
		}

		visible := false
		// Check all topics including topics[0].
		// For normal events, topics[0] is the keccak256 event signature hash —
		// a value that practically never has 12 leading zero bytes, so
		// topicMatchesAddress will reject it without false positives.
		// For anonymous events (Solidity `anonymous` keyword), there is no
		// signature hash and topics[0] is the first indexed parameter, which
		// may be an address — so we must include it.
		for i := 0; i < len(entry.Topics); i++ {
			if topicMatchesAddress(entry.Topics[i], addrSet) {
				visible = true
				break
			}
		}
		if visible {
			filtered = append(filtered, rawLog)
		}
	}

	filteredJSON, err := json.Marshal(filtered)
	if err != nil {
		return responseBody
	}

	result := json.RawMessage(filteredJSON)
	out, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{
		JSONRPC: "2.0",
		ID:      resp.ID,
		Result:  result,
	})
	if err != nil {
		return responseBody
	}
	return out
}

// FilterBlockTransactions filters an eth_getBlockByNumber or eth_getBlockByHash response.
// When the block includes full transaction objects (fullTxObjects=true), this removes
// transactions where the user is not a participant (from/to don't match linked addresses).
// When the block includes only transaction hashes (fullTxObjects=false), passes through
// unchanged — hashes are not sensitive without the corresponding calldata.
// If the result is null or not a block object, passes through unchanged.
func FilterBlockTransactions(responseBody []byte, userAddresses []string) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return responseBody
	}
	if resp.Error != nil || resp.Result == nil {
		return responseBody
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return responseBody
	}

	// Parse the block as a map to preserve all fields
	var block map[string]json.RawMessage
	if err := json.Unmarshal(raw, &block); err != nil {
		return responseBody
	}

	txsRaw, ok := block["transactions"]
	if !ok {
		return responseBody // no transactions field
	}

	// Check if transactions are objects or hashes (strings)
	var rawTxs []json.RawMessage
	if err := json.Unmarshal(txsRaw, &rawTxs); err != nil || len(rawTxs) == 0 {
		return responseBody // empty or unparseable — pass through
	}

	// Peek at first element to determine if full objects or hashes
	first := bytes.TrimSpace(rawTxs[0])
	if len(first) == 0 || first[0] == '"' {
		// Transaction hashes (strings) — not sensitive, pass through
		return responseBody
	}

	// Full transaction objects — filter to only user's transactions
	addrSet := addrSetFromLinked(userAddresses)
	filtered := make([]json.RawMessage, 0, len(rawTxs))
	for _, rawTx := range rawTxs {
		var tx struct {
			From string `json:"from"`
			To   string `json:"to"`
		}
		if err := json.Unmarshal(rawTx, &tx); err != nil {
			continue
		}
		from := strings.ToLower(tx.From)
		to := strings.ToLower(tx.To)
		if addrSet[from] || (to != "" && addrSet[to]) {
			filtered = append(filtered, rawTx)
		}
	}

	filteredTxJSON, err := json.Marshal(filtered)
	if err != nil {
		return responseBody
	}
	block["transactions"] = filteredTxJSON

	blockJSON, err := json.Marshal(block)
	if err != nil {
		return responseBody
	}

	blockResult := json.RawMessage(blockJSON)
	blockOut, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{
		JSONRPC: "2.0",
		ID:      resp.ID,
		Result:  blockResult,
	})
	if err != nil {
		return responseBody
	}
	return blockOut
}

// FilterBlockReceipts filters an eth_getBlockReceipts response.
// Non-participant receipts are removed from the array entirely, consistent
// with how FilterBlockTransactions removes non-participant transactions.
// If the result is null or not an array, passes through unchanged.
func FilterBlockReceipts(responseBody []byte, userAddresses []string) []byte {
	var resp struct {
		JSONRPC string           `json:"jsonrpc"`
		ID      json.RawMessage  `json:"id"`
		Result  *json.RawMessage `json:"result"`
		Error   *json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(responseBody, &resp); err != nil {
		return responseBody
	}
	if resp.Error != nil || resp.Result == nil {
		return responseBody
	}
	raw := []byte(*resp.Result)
	if string(raw) == "null" {
		return responseBody
	}

	var rawReceipts []json.RawMessage
	if err := json.Unmarshal(raw, &rawReceipts); err != nil {
		return responseBody // not an array — pass through
	}

	addrSet := addrSetFromLinked(userAddresses)
	receiptsFiltered := make([]json.RawMessage, 0, len(rawReceipts))

	for _, rawReceipt := range rawReceipts {
		var receipt struct {
			From string `json:"from"`
			To   string `json:"to"`
		}
		if err := json.Unmarshal(rawReceipt, &receipt); err != nil {
			continue // skip malformed entries
		}
		from := strings.ToLower(receipt.From)
		to := strings.ToLower(receipt.To)

		if addrSet[from] || (to != "" && addrSet[to]) {
			receiptsFiltered = append(receiptsFiltered, rawReceipt)
		}
		// Non-participant: omit entirely (consistent with FilterBlockTransactions).
	}

	receiptsJSON, err := json.Marshal(receiptsFiltered)
	if err != nil {
		return responseBody
	}

	receiptsResult := json.RawMessage(receiptsJSON)
	receiptsOut, err := json.Marshal(struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
	}{
		JSONRPC: "2.0",
		ID:      resp.ID,
		Result:  receiptsResult,
	})
	if err != nil {
		return responseBody
	}
	return receiptsOut
}
