package audit

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedactParams_RawTransaction(t *testing.T) {
	params := []any{"0xf86c0a8502540be400825208948d97689c9818892b700e27f316cc3e41e17fbeb9872386f26fc1000080820a96a0f0c7f3e0c7b5f6d3a3b5c4e3d2f1e0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4a0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0"}

	result := RedactParams("eth_sendRawTransaction", params)
	require.NotNil(t, result)

	var parsed []any
	err := json.Unmarshal(result, &parsed)
	require.NoError(t, err)
	require.Len(t, parsed, 1)

	rawTx, ok := parsed[0].(string)
	require.True(t, ok)
	assert.Equal(t, "0xf86c0a8502540be400...", rawTx)
}

func TestRedactParams_SendTransaction(t *testing.T) {
	params := []any{map[string]any{
		"from":  "0x1234567890abcdef1234567890abcdef12345678",
		"to":    "0xabcdef1234567890abcdef1234567890abcdef12",
		"value": "0x1000",
		"data":  "0xa9059cbb000000000000000000000000abcdef1234567890abcdef1234567890abcdef120000000000000000000000000000000000000000000000000000000000001000",
	}}

	result := RedactParams("eth_sendTransaction", params)
	require.NotNil(t, result)

	var parsed []any
	err := json.Unmarshal(result, &parsed)
	require.NoError(t, err)
	require.Len(t, parsed, 1)

	txObj, ok := parsed[0].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "0x1234567890abcdef1234567890abcdef12345678", txObj["from"])
	assert.Equal(t, "0xabcdef1234567890abcdef1234567890abcdef12", txObj["to"])
	assert.Equal(t, "0x1000", txObj["value"])

	data, ok := txObj["data"].(string)
	require.True(t, ok)
	assert.Equal(t, "0xa9059cbb...", data)
}

func TestRedactParams_OtherMethods(t *testing.T) {
	params := []any{"0x1234", "latest"}

	result := RedactParams("eth_getBalance", params)
	require.NotNil(t, result)

	var parsed []any
	err := json.Unmarshal(result, &parsed)
	require.NoError(t, err)
	assert.Equal(t, []any{"0x1234", "latest"}, parsed)
}

func TestRedactParams_EmptyParams(t *testing.T) {
	result := RedactParams("eth_blockNumber", nil)
	assert.Nil(t, result)

	result = RedactParams("eth_blockNumber", []any{})
	assert.Nil(t, result)
}

func TestRedactParams_ShortData(t *testing.T) {
	params := []any{map[string]any{
		"from": "0x1234",
		"to":   "0x5678",
		"data": "0x1234",
	}}

	result := RedactParams("eth_sendTransaction", params)
	require.NotNil(t, result)

	var parsed []any
	err := json.Unmarshal(result, &parsed)
	require.NoError(t, err)

	txObj := parsed[0].(map[string]any)
	assert.Equal(t, "0x1234", txObj["data"])
}
