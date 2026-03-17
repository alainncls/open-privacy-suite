package explorer

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// mockDB implements Database for testing
type mockDB struct {
	visMap      VisibilityMap
	err         error
	linkedAddrs []string // addresses returned by GetLinkedAddresses
}

func (m *mockDB) GetBatchVisibility(_ context.Context, _ string, _ []string) (VisibilityMap, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.visMap, nil
}

func (m *mockDB) GetLinkedAddresses(_ context.Context, _ string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.linkedAddrs, nil
}

// mockContractStore implements ContractStore for testing
type mockContractStore struct {
	contracts map[string]*Contract // keyed by lowercase address
}

func (m *mockContractStore) GetContract(_ context.Context, address string) (*Contract, error) {
	if m.contracts == nil {
		return nil, nil
	}
	c := m.contracts[strings.ToLower(address)]
	return c, nil
}

func newEngine(visMap VisibilityMap) *RedactionEngine {
	return &RedactionEngine{store: nil, db: &mockDB{visMap: visMap}}
}

func newEngineWithLinkedAddrs(visMap VisibilityMap, linkedAddrs []string) *RedactionEngine {
	return &RedactionEngine{store: nil, db: &mockDB{visMap: visMap, linkedAddrs: linkedAddrs}}
}

func newEngineWithStore(visMap VisibilityMap, store ContractStore) *RedactionEngine {
	return &RedactionEngine{store: store, db: &mockDB{visMap: visMap}}
}

func newEngineErr(err error) *RedactionEngine {
	return &RedactionEngine{store: nil, db: &mockDB{err: err}}
}

// eventTopic0 computes keccak256 of an event signature, returning "0x"-prefixed hex.
func eventTopic0(sig string) string {
	return "0x" + hex.EncodeToString(crypto.Keccak256([]byte(sig)))
}

// encodeAddress encodes an Ethereum address as a zero-padded 32-byte hex string (no 0x prefix).
func encodeAddressSlot(addr string) string {
	addr = strings.TrimPrefix(strings.ToLower(addr), "0x")
	return strings.Repeat("0", 24) + strings.ToLower(addr)
}

// encodeUint256Slot encodes a uint256 value as a 32-byte zero-padded hex string (no 0x prefix).
func encodeUint256Slot(val uint64) string {
	return strings.Repeat("0", 56) + hex.EncodeToString([]byte{
		byte(val >> 56), byte(val >> 48), byte(val >> 40), byte(val >> 32),
		byte(val >> 24), byte(val >> 16), byte(val >> 8), byte(val),
	})
}

func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// RedactTransactions
// ---------------------------------------------------------------------------

func TestRedactTransactions_Empty(t *testing.T) {
	engine := newEngine(nil)
	result, err := engine.RedactTransactions(context.Background(), nil, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil, got %v", result)
	}
}

func TestRedactTransactions_FullVisibility(t *testing.T) {
	addr1 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addr2 := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{
		{Hash: "0x01", From: addr1, To: strPtr(addr2), Value: "1000", InputData: "0xdeadbeef"},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].From != addr1 {
		t.Errorf("From mismatch: %s", result[0].From)
	}
	if *result[0].To != addr2 {
		t.Errorf("To mismatch: %s", *result[0].To)
	}
	if result[0].Value != "1000" {
		t.Errorf("Value should be unchanged, got %s", result[0].Value)
	}
	if result[0].InputData != "0xdeadbeef" {
		t.Errorf("InputData should be unchanged, got %s", result[0].InputData)
	}
}

func TestRedactTransactions_HiddenFrom_KeepsWithPrivate(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (hidden from, public to → keep), got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE], got %s", result[0].From)
	}
	if *result[0].To != to {
		t.Errorf("To should be unchanged, got %s", *result[0].To)
	}
	if result[0].Value != "" {
		t.Errorf("Value should be stripped, got %s", result[0].Value)
	}
}

func TestRedactTransactions_HiddenTo_KeepsWithPrivate(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (public from, hidden to → keep), got %d", len(result))
	}
	if result[0].From != from {
		t.Errorf("From should be unchanged, got %s", result[0].From)
	}
	if *result[0].To != "[PRIVATE]" {
		t.Errorf("To should be [PRIVATE], got %s", *result[0].To)
	}
	if result[0].Value != "" {
		t.Errorf("Value should be stripped, got %s", result[0].Value)
	}
}

func TestRedactTransactions_BothHidden_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 txs (both hidden → drop), got %d", len(result))
	}
}

func TestRedactTransactions_HiddenFrom_PublicTo_ShowsPrivate(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	errStr := "execution reverted"
	revertStr := "out of gas"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{{
		Hash:         "0x01",
		From:         from,
		To:           strPtr(to),
		Value:        "1000",
		InputData:    "0xdeadbeef",
		Error:        &errStr,
		RevertReason: &revertStr,
	}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	tx := result[0]
	if tx.From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE], got %s", tx.From)
	}
	if *tx.To != to {
		t.Errorf("To should be unchanged, got %s", *tx.To)
	}
	if tx.Value != "" {
		t.Errorf("Value should be stripped, got %s", tx.Value)
	}
	if tx.InputData != "" {
		t.Errorf("InputData should be stripped, got %s", tx.InputData)
	}
	if tx.Error != nil {
		t.Errorf("Error should be nil")
	}
	if tx.RevertReason != nil {
		t.Errorf("RevertReason should be nil")
	}
}

func TestRedactTransactions_HiddenTo_PublicFrom_ShowsPrivate(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000", InputData: "0xaa"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	tx := result[0]
	if tx.From != from {
		t.Errorf("From should be unchanged, got %s", tx.From)
	}
	if *tx.To != "[PRIVATE]" {
		t.Errorf("To should be [PRIVATE], got %s", *tx.To)
	}
	if tx.Value != "" {
		t.Errorf("Value should be stripped, got %s", tx.Value)
	}
	if tx.InputData != "" {
		t.Errorf("InputData should be stripped, got %s", tx.InputData)
	}
}

func TestRedactTransactions_RedactedFrom_StripsData(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	errStr := "execution reverted"
	revertStr := "out of gas"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{{
		Hash:         "0x01",
		From:         from,
		To:           strPtr(to),
		Value:        "1000",
		InputData:    "0xdeadbeef",
		Error:        &errStr,
		RevertReason: &revertStr,
	}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	tx := result[0]
	if tx.From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE], got %s", tx.From)
	}
	if tx.Value != "" {
		t.Errorf("Value should be stripped, got %s", tx.Value)
	}
	if tx.InputData != "" {
		t.Errorf("InputData should be stripped, got %s", tx.InputData)
	}
	if tx.Error != nil {
		t.Errorf("Error should be nil")
	}
	if tx.RevertReason != nil {
		t.Errorf("RevertReason should be nil")
	}
	// To address unchanged (full visibility)
	if *tx.To != to {
		t.Errorf("To should be unchanged, got %s", *tx.To)
	}
}

func TestRedactTransactions_RedactedTo_StripsData(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000", InputData: "0xaa"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	tx := result[0]
	if *tx.To != "[PRIVATE]" {
		t.Errorf("To should be [PRIVATE], got %s", *tx.To)
	}
	if tx.Value != "" {
		t.Errorf("Value should be stripped, got %s", tx.Value)
	}
	if tx.From != from {
		t.Errorf("From should be unchanged, got %s", tx.From)
	}
}

func TestRedactTransactions_PseudonymousAddress(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityPseudonymous,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "500"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	expectedPseudonym := GeneratePseudonym(from)
	if result[0].From != expectedPseudonym {
		t.Errorf("From should be pseudonym %q, got %q", expectedPseudonym, result[0].From)
	}
	// Value not stripped for pseudonymous
	if result[0].Value != "500" {
		t.Errorf("Value should be unchanged for pseudonymous, got %s", result[0].Value)
	}
}

func TestRedactTransactions_NilTo(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: nil, Value: "0"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (nil to is fine), got %d", len(result))
	}
	if result[0].To != nil {
		t.Errorf("To should remain nil")
	}
}

func TestRedactTransactions_DBError(t *testing.T) {
	engine := newEngineErr(errors.New("db unavailable"))
	txs := []Transaction{{Hash: "0x01", From: "0xaa", To: strPtr("0xbb")}}
	_, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err == nil {
		t.Error("expected error from DB")
	}
}

func TestRedactTransactions_MultipleTxsMixed(t *testing.T) {
	addrFull := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addrHidden := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	addrRedacted := "0xcccccccccccccccccccccccccccccccccccccccc"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
		"0xcccccccccccccccccccccccccccccccccccccccc": VisibilityRedacted,
	})

	txs := []Transaction{
		{Hash: "0x01", From: addrFull, To: strPtr(addrFull)},       // keep, full
		{Hash: "0x02", From: addrFull, To: strPtr(addrHidden)},     // keep, to=[PRIVATE]
		{Hash: "0x03", From: addrFull, To: strPtr(addrRedacted)},   // keep, redacted to
		{Hash: "0x04", From: addrHidden, To: strPtr(addrFull)},     // keep, from=[PRIVATE]
		{Hash: "0x05", From: addrHidden, To: strPtr(addrHidden)},   // drop (both hidden)
	}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 4 {
		t.Fatalf("expected 4 txs (0x05 dropped, rest kept), got %d", len(result))
	}
	if result[0].Hash != "0x01" {
		t.Errorf("first result should be 0x01, got %s", result[0].Hash)
	}
	if result[1].Hash != "0x02" {
		t.Errorf("second result should be 0x02, got %s", result[1].Hash)
	}
	if *result[1].To != "[PRIVATE]" {
		t.Errorf("0x02 To should be [PRIVATE], got %s", *result[1].To)
	}
	if result[2].Hash != "0x03" {
		t.Errorf("third result should be 0x03, got %s", result[2].Hash)
	}
	if result[3].Hash != "0x04" {
		t.Errorf("fourth result should be 0x04, got %s", result[3].Hash)
	}
	if result[3].From != "[PRIVATE]" {
		t.Errorf("0x04 From should be [PRIVATE], got %s", result[3].From)
	}
}

// ---------------------------------------------------------------------------
// Nonce redaction
// ---------------------------------------------------------------------------

func u64ptr(n uint64) *uint64 { return &n }

func TestRedactTransactions_HiddenFrom_NilsNonce(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityHidden,
		to:   VisibilityFull,
	})

	nonce := u64ptr(42)
	txs := []Transaction{
		{Hash: "0x01", From: from, To: strPtr(to), Value: "100", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].Nonce != nil {
		t.Errorf("nonce must be nil when sender is hidden, got %v", *result[0].Nonce)
	}
}

func TestRedactTransactions_HiddenTo_PreservesNonce(t *testing.T) {
	// When the RECEIVER is hidden but the sender is public, nonce is not stripped
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityFull,
		to:   VisibilityHidden,
	})

	nonce := u64ptr(7)
	txs := []Transaction{
		{Hash: "0x01", From: from, To: strPtr(to), Value: "100", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].Nonce == nil || *result[0].Nonce != 7 {
		t.Errorf("nonce should be preserved when only receiver is hidden, got %v", result[0].Nonce)
	}
}

func TestRedactTransactions_RedactedFrom_NilsNonce(t *testing.T) {
	// VisibilityRedacted (address truncated, data stripped) also hides nonce
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		from: VisibilityRedacted,
		to:   VisibilityFull,
	})

	nonce := u64ptr(99)
	txs := []Transaction{
		{Hash: "0x01", From: from, To: strPtr(to), Value: "200", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].Nonce != nil {
		t.Errorf("nonce must be nil when sender is redacted, got %v", *result[0].Nonce)
	}
}

// ---------------------------------------------------------------------------
// RedactTransfers
// ---------------------------------------------------------------------------

func TestRedactTransfers_Empty(t *testing.T) {
	engine := newEngine(nil)
	result, err := engine.RedactTransfers(context.Background(), nil, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil")
	}
}

func TestRedactTransfers_HiddenFrom_KeepsWithPrivate(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "100"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer (hidden from, public to → keep), got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE], got %s", result[0].From)
	}
	if result[0].To != to {
		t.Errorf("To should be unchanged, got %s", result[0].To)
	}
	if result[0].Value != "" {
		t.Errorf("Value should be stripped, got %s", result[0].Value)
	}
}

func TestRedactTransfers_BothHidden_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "100"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 transfers (both hidden → drop), got %d", len(result))
	}
}

func TestRedactTransfers_HiddenFrom_PublicTo_ShowsPrivate(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "500"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer, got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE], got %s", result[0].From)
	}
	if result[0].To != to {
		t.Errorf("To should be unchanged, got %s", result[0].To)
	}
	if result[0].Value != "" {
		t.Errorf("Value should be stripped, got %s", result[0].Value)
	}
}

func TestRedactTransfers_RedactedStripsValue(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "500"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer, got %d", len(result))
	}
	if result[0].To != "[PRIVATE]" {
		t.Errorf("To should be [PRIVATE], got %s", result[0].To)
	}
	if result[0].Value != "" {
		t.Errorf("Value should be stripped, got %s", result[0].Value)
	}
	if result[0].From != from {
		t.Errorf("From should be unchanged, got %s", result[0].From)
	}
}

func TestRedactTransfers_FullVisibilityUnchanged(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "999"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer, got %d", len(result))
	}
	if result[0].From != from || result[0].To != to || result[0].Value != "999" {
		t.Errorf("transfer should be unchanged: %+v", result[0])
	}
}

func TestRedactTransfers_DBError(t *testing.T) {
	engine := newEngineErr(errors.New("db error"))
	transfers := []TokenTransfer{{ID: 1, From: "0xaa", To: "0xbb"}}
	_, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// RedactInternalTransactions
// ---------------------------------------------------------------------------

func TestRedactInternalTransactions_Empty(t *testing.T) {
	engine := newEngine(nil)
	result, err := engine.RedactInternalTransactions(context.Background(), nil, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil")
	}
}

func TestRedactInternalTransactions_HiddenFrom_KeepsWithPrivate(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := "0xdeadbeef"
	output := "0x01"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "100", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 (hidden from, public to → keep), got %d", len(result))
	}
	itx := result[0]
	if itx.From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE], got %s", itx.From)
	}
	if *itx.To != to {
		t.Errorf("To should be unchanged, got %s", *itx.To)
	}
	if itx.Value != "" {
		t.Errorf("Value should be stripped, got %s", itx.Value)
	}
	if itx.Input != nil {
		t.Errorf("Input should be nil")
	}
	if itx.Output != nil {
		t.Errorf("Output should be nil")
	}
}

func TestRedactInternalTransactions_BothHidden_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "100"}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 (both hidden → drop), got %d", len(result))
	}
}

func TestRedactInternalTransactions_HiddenFrom_PublicTo_ShowsPrivate(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := "0xdeadbeef"
	output := "0x01"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "200", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	itx := result[0]
	if itx.From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE], got %s", itx.From)
	}
	if *itx.To != to {
		t.Errorf("To should be unchanged, got %s", *itx.To)
	}
	if itx.Value != "" {
		t.Errorf("Value should be stripped, got %s", itx.Value)
	}
	if itx.Input != nil {
		t.Errorf("Input should be nil")
	}
	if itx.Output != nil {
		t.Errorf("Output should be nil")
	}
}

func TestRedactInternalTransactions_RedactedStripsData(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := "0xdeadbeef"
	output := "0x01"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "100", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	itx := result[0]
	if *itx.To != "[PRIVATE]" {
		t.Errorf("To should be [PRIVATE], got %s", *itx.To)
	}
	if itx.Value != "" {
		t.Errorf("Value should be stripped, got %s", itx.Value)
	}
	if itx.Input != nil {
		t.Errorf("Input should be nil")
	}
	if itx.Output != nil {
		t.Errorf("Output should be nil")
	}
}

func TestRedactInternalTransactions_NilTo(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: nil, Value: "0"}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].To != nil {
		t.Errorf("To should remain nil")
	}
}

// ---------------------------------------------------------------------------
// RedactLogs
// ---------------------------------------------------------------------------

func TestRedactLogs_Empty(t *testing.T) {
	engine := newEngine(nil)
	result, err := engine.RedactLogs(context.Background(), nil, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil")
	}
}

func TestRedactLogs_HiddenDrops(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
	})

	topic := "0xdeadbeef"
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "somedata"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 logs, got %d", len(result))
	}
}

func TestRedactLogs_RedactedStripsTopicsAndData(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
	})

	topic0 := "0xabcd"
	topic1 := "0x1234"
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic0, Topic1: &topic1, Data: "encoded_data"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	l := result[0]
	if l.Address != "[PRIVATE]" {
		t.Errorf("Address should be [PRIVATE], got %s", l.Address)
	}
	if l.Topic0 != nil {
		t.Errorf("Topic0 should be nil")
	}
	if l.Topic1 != nil {
		t.Errorf("Topic1 should be nil")
	}
	if l.Data != "" {
		t.Errorf("Data should be stripped, got %s", l.Data)
	}
}

func TestRedactLogs_FullUnchanged(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
	})

	topic := "0xabcd"
	logs := []Log{{ID: 1, Address: addr, Topic0: &topic, Data: "0xff"}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Address != addr {
		t.Errorf("Address should be unchanged, got %s", result[0].Address)
	}
	if *result[0].Topic0 != topic {
		t.Errorf("Topic0 should be unchanged, got %s", *result[0].Topic0)
	}
	if result[0].Data != "0xff" {
		t.Errorf("Data should be unchanged, got %s", result[0].Data)
	}
}

func TestRedactLogs_DBError(t *testing.T) {
	engine := newEngineErr(errors.New("db error"))
	logs := []Log{{ID: 1, Address: "0xaa", Data: "data"}}
	_, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// RedactLogs — ABI-based Data Field scanning
// ---------------------------------------------------------------------------

// testABI is a minimal ABI JSON for event: PrivateTransfer(address indexed from, address to, uint256 value)
// topic0 = keccak256("PrivateTransfer(address,address,uint256)")
// data   = abi.encode(to address, value) — 32 bytes for address + 32 bytes for uint256
const testEventABI = `[{"type":"event","name":"PrivateTransfer","inputs":[{"name":"from","type":"address","indexed":true},{"name":"to","type":"address","indexed":false},{"name":"value","type":"uint256","indexed":false}]}]`

func TestRedactLogs_ABIDataPrivateAddress_Zeroed(t *testing.T) {
	emitter := "0xcccccccccccccccccccccccccccccccccccccccc"
	privateAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	topic0 := eventTopic0("PrivateTransfer(address,address,uint256)")

	// data = abi.encode(privateAddr, 1000)
	dataHex := "0x" + encodeAddressSlot(privateAddr) + encodeUint256Slot(1000)
	zeroedSlot := strings.Repeat("0", 64)

	store := &mockContractStore{contracts: map[string]*Contract{
		emitter: {Address: emitter, ABI: []byte(testEventABI)},
	}}
	engine := newEngineWithStore(VisibilityMap{
		emitter:     VisibilityFull,
		privateAddr: VisibilityRedacted,
	}, store)

	logs := []Log{{ID: 1, Address: emitter, Topic0: &topic0, Data: dataHex}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log, got %d", len(result))
	}
	// The address slot (first 32 bytes) should be zeroed; value slot unchanged.
	expectedData := "0x" + zeroedSlot + encodeUint256Slot(1000)
	if result[0].Data != expectedData {
		t.Errorf("expected data %q, got %q", expectedData, result[0].Data)
	}
}

func TestRedactLogs_ABIDataPublicAddress_Unchanged(t *testing.T) {
	emitter := "0xcccccccccccccccccccccccccccccccccccccccc"
	publicAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	topic0 := eventTopic0("PrivateTransfer(address,address,uint256)")

	dataHex := "0x" + encodeAddressSlot(publicAddr) + encodeUint256Slot(500)

	store := &mockContractStore{contracts: map[string]*Contract{
		emitter: {Address: emitter, ABI: []byte(testEventABI)},
	}}
	engine := newEngineWithStore(VisibilityMap{
		emitter:    VisibilityFull,
		publicAddr: VisibilityFull,
	}, store)

	logs := []Log{{ID: 1, Address: emitter, Topic0: &topic0, Data: dataHex}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log, got %d", len(result))
	}
	if result[0].Data != dataHex {
		t.Errorf("data should be unchanged for public address, got %q", result[0].Data)
	}
}

func TestRedactLogs_NoABI_DataUnchanged(t *testing.T) {
	emitter := "0xcccccccccccccccccccccccccccccccccccccccc"
	topic0 := eventTopic0("PrivateTransfer(address,address,uint256)")
	dataHex := "0x" + encodeAddressSlot("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") + encodeUint256Slot(999)

	// Store returns nil contract (no ABI registered)
	store := &mockContractStore{contracts: map[string]*Contract{}}
	engine := newEngineWithStore(VisibilityMap{
		emitter: VisibilityFull,
	}, store)

	logs := []Log{{ID: 1, Address: emitter, Topic0: &topic0, Data: dataHex}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log, got %d", len(result))
	}
	if result[0].Data != dataHex {
		t.Errorf("data should be unchanged when no ABI is registered, got %q", result[0].Data)
	}
}

func TestRedactLogs_UnknownTopic0_DataUnchanged(t *testing.T) {
	emitter := "0xcccccccccccccccccccccccccccccccccccccccc"
	unknownTopic0 := "0x" + strings.Repeat("ab", 32) // not a matching event
	dataHex := "0x" + encodeAddressSlot("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa") + encodeUint256Slot(1)

	store := &mockContractStore{contracts: map[string]*Contract{
		emitter: {Address: emitter, ABI: []byte(testEventABI)},
	}}
	engine := newEngineWithStore(VisibilityMap{
		emitter: VisibilityFull,
	}, store)

	logs := []Log{{ID: 1, Address: emitter, Topic0: &unknownTopic0, Data: dataHex}}
	result, err := engine.RedactLogs(context.Background(), logs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log, got %d", len(result))
	}
	if result[0].Data != dataHex {
		t.Errorf("data should be unchanged when topic0 does not match any event, got %q", result[0].Data)
	}
}

// ---------------------------------------------------------------------------
// RedactAddress
// ---------------------------------------------------------------------------

func TestRedactAddress_Full(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
	})

	result, err := engine.RedactAddress(context.Background(), addr, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != addr {
		t.Errorf("expected %s, got %s", addr, result)
	}
}

func TestRedactAddress_Redacted(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
	})

	result, err := engine.RedactAddress(context.Background(), addr, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != "[PRIVATE]" {
		t.Errorf("expected [PRIVATE], got %s", result)
	}
}

func TestRedactAddress_Pseudonymous(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityPseudonymous,
	})

	result, err := engine.RedactAddress(context.Background(), addr, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	expected := GeneratePseudonym(addr)
	if result != expected {
		t.Errorf("expected %s, got %s", expected, result)
	}
}

func TestRedactAddress_Hidden(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
	})

	result, err := engine.RedactAddress(context.Background(), addr, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != "[PRIVATE]" {
		t.Errorf("expected [PRIVATE] for hidden, got %s", result)
	}
}

func TestRedactAddress_DBError(t *testing.T) {
	engine := newEngineErr(errors.New("db error"))
	result, err := engine.RedactAddress(context.Background(), "0xaa", "did:test")
	if err == nil {
		t.Error("expected error")
	}
	if result != "[REDACTED]" {
		t.Errorf("expected [REDACTED] fallback on error, got %s", result)
	}
}

// ---------------------------------------------------------------------------
// RedactTokenHolders
// ---------------------------------------------------------------------------

func TestRedactTokenHolders_Empty(t *testing.T) {
	engine := newEngine(nil)
	result, err := engine.RedactTokenHolders(context.Background(), nil, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != nil {
		t.Errorf("expected nil")
	}
}

func TestRedactTokenHolders_HiddenDrops(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
	})

	holders := []TokenHolder{{Address: addr, Balance: "100"}}
	result, err := engine.RedactTokenHolders(context.Background(), holders, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 holders, got %d", len(result))
	}
}

func TestRedactTokenHolders_RedactedMasksAddressAndStripsBalance(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
	})

	holders := []TokenHolder{{Address: addr, Balance: "200", Percentage: 5.5}}
	result, err := engine.RedactTokenHolders(context.Background(), holders, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Address != "[PRIVATE]" {
		t.Errorf("Address should be [PRIVATE], got %s", result[0].Address)
	}
	// Balance and percentage stripped for redacted holders — reveals financial position
	if result[0].Balance != "" {
		t.Errorf("Balance should be stripped for redacted holder, got %s", result[0].Balance)
	}
	if result[0].Percentage != 0 {
		t.Errorf("Percentage should be 0 for redacted holder, got %f", result[0].Percentage)
	}
}

func TestRedactTokenHolders_PseudonymousPreservesBalance(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityPseudonymous,
	})

	holders := []TokenHolder{{Address: addr, Balance: "500", Percentage: 12.3}}
	result, err := engine.RedactTokenHolders(context.Background(), holders, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	expectedPseudonym := GeneratePseudonym(addr)
	if result[0].Address != expectedPseudonym {
		t.Errorf("Address should be pseudonym %q, got %q", expectedPseudonym, result[0].Address)
	}
	// Balance preserved for pseudonymous — pattern analysis is the use case
	if result[0].Balance != "500" {
		t.Errorf("Balance should be preserved for pseudonymous holder, got %s", result[0].Balance)
	}
	if result[0].Percentage != 12.3 {
		t.Errorf("Percentage should be preserved for pseudonymous holder, got %f", result[0].Percentage)
	}
}

func TestRedactTokenHolders_FullUnchanged(t *testing.T) {
	addr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
	})

	holders := []TokenHolder{{Address: addr, Balance: "300", Percentage: 10.0}}
	result, err := engine.RedactTokenHolders(context.Background(), holders, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Address != addr {
		t.Errorf("Address should be unchanged, got %s", result[0].Address)
	}
}

func TestRedactTokenHolders_DBError(t *testing.T) {
	engine := newEngineErr(errors.New("db error"))
	holders := []TokenHolder{{Address: "0xaa", Balance: "1"}}
	_, err := engine.RedactTokenHolders(context.Background(), holders, "did:test")
	if err == nil {
		t.Error("expected error")
	}
}

// ---------------------------------------------------------------------------
// applyRedaction (via RedactAddress — indirect testing)
// ---------------------------------------------------------------------------

func TestApplyRedaction_DefaultFallback(t *testing.T) {
	// An address not in the map returns zero value VisibilityLevel (""),
	// which hits the default case in applyRedaction and returns "[PRIVATE]"
	engine := newEngine(VisibilityMap{}) // empty map
	result, err := engine.RedactAddress(context.Background(), "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if result != "[PRIVATE]" {
		t.Errorf("unknown visibility should default to [PRIVATE], got %s", result)
	}
}

// ---------------------------------------------------------------------------
// Participant visibility — viewer sees counterparty in their own transactions
// ---------------------------------------------------------------------------

func TestRedactTransactions_ParticipantSeesCounterparty(t *testing.T) {
	// Alice (viewer) sends to Bob. Bob's address is hidden globally,
	// but Alice should see Bob's address because Alice is the sender.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityFull,
		bob:   VisibilityHidden,
	}, []string{alice})

	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "1000", InputData: "0xdeadbeef"},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].From != alice {
		t.Errorf("From should be unchanged, got %s", result[0].From)
	}
	if *result[0].To != bob {
		t.Errorf("To should be Bob's real address (participant visibility), got %s", *result[0].To)
	}
	// Value and input should be preserved since both sides are now VisibilityFull
	if result[0].Value != "1000" {
		t.Errorf("Value should be preserved for participant, got %s", result[0].Value)
	}
	if result[0].InputData != "0xdeadbeef" {
		t.Errorf("InputData should be preserved for participant, got %s", result[0].InputData)
	}
}

func TestRedactTransactions_ParticipantSeesCounterparty_Receiver(t *testing.T) {
	// Bob (viewer) receives from Alice. Alice's address is hidden globally,
	// but Bob should see Alice's address because Bob is the receiver.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{bob})

	nonce := u64ptr(42)
	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "500", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].From != alice {
		t.Errorf("From should be Alice's real address (participant visibility), got %s", result[0].From)
	}
	if *result[0].To != bob {
		t.Errorf("To should be unchanged, got %s", *result[0].To)
	}
	if result[0].Value != "500" {
		t.Errorf("Value should be preserved for participant, got %s", result[0].Value)
	}
	// Nonce must be stripped — the sender is base-level hidden, and nonce reveals
	// their lifetime tx count. The participant override shows the address, not metadata.
	if result[0].Nonce != nil {
		t.Errorf("Nonce must be nil when sender is base-level hidden (participant override), got %v", *result[0].Nonce)
	}
}

func TestRedactTransactions_ParticipantNonceStripped_SenderViewing(t *testing.T) {
	// Alice (viewer, sender) sends to Bob (hidden). Alice sees Bob's address
	// via participant visibility, but Alice's own nonce should be preserved
	// (it's her own nonce, not private from her).
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityFull,
		bob:   VisibilityHidden,
	}, []string{alice})

	nonce := u64ptr(10)
	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "100", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	// Alice's own nonce should be preserved — it's her own data
	if result[0].Nonce == nil || *result[0].Nonce != 10 {
		t.Errorf("Sender's own nonce should be preserved, got %v", result[0].Nonce)
	}
}

func TestRedactTransactions_ParticipantNonceStripped_ReceiverViewingRedactedSender(t *testing.T) {
	// Bob (viewer, receiver) sees tx from Alice (redacted). Alice's nonce must be stripped.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityRedacted,
		bob:   VisibilityFull,
	}, []string{bob})

	nonce := u64ptr(99)
	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "200", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].Nonce != nil {
		t.Errorf("Nonce must be nil when sender is base-level redacted (participant override), got %v", *result[0].Nonce)
	}
}

func TestRedactTransactions_NonParticipantDoesNotSeeHiddenAddresses(t *testing.T) {
	// Charlie (viewer) is not a participant. Alice and Bob are from/to.
	// Alice is hidden — Charlie should NOT see Alice's real address.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	charlie := "0xcccccccccccccccccccccccccccccccccccccccc"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{charlie})

	nonce := u64ptr(7)
	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "1000", Nonce: nonce},
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:charlie")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE] for non-participant, got %s", result[0].From)
	}
	if *result[0].To != bob {
		t.Errorf("To should be unchanged, got %s", *result[0].To)
	}
	if result[0].Value != "" {
		t.Errorf("Value should be stripped (one side hidden, non-participant), got %s", result[0].Value)
	}
	if result[0].Nonce != nil {
		t.Errorf("Nonce must be nil for non-participant when sender is hidden, got %v", *result[0].Nonce)
	}
}

func TestRedactTransactions_ParticipantVisibilityDoesNotLeakToOtherTxs(t *testing.T) {
	// Alice (viewer) is participant in tx1 (Alice -> Bob) but NOT in tx2 (Carol -> Bob).
	// Bob is hidden globally. Alice should see Bob in tx1 but NOT in tx2.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	carol := "0xcccccccccccccccccccccccccccccccccccccccc"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityFull,
		bob:   VisibilityHidden,
		carol: VisibilityFull,
	}, []string{alice})

	nonce5 := u64ptr(5)
	nonce8 := u64ptr(8)
	txs := []Transaction{
		{Hash: "0x01", From: alice, To: strPtr(bob), Value: "100", Nonce: nonce5},  // Alice is participant
		{Hash: "0x02", From: carol, To: strPtr(bob), Value: "200", Nonce: nonce8},  // Alice is NOT participant
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 txs, got %d", len(result))
	}

	// tx1: Alice is participant (sender), Bob should be visible
	tx1 := result[0]
	if tx1.Hash != "0x01" {
		t.Fatalf("expected tx1 hash 0x01, got %s", tx1.Hash)
	}
	if *tx1.To != bob {
		t.Errorf("tx1: To should be Bob's real address (participant), got %s", *tx1.To)
	}
	if tx1.Value != "100" {
		t.Errorf("tx1: Value should be preserved for participant, got %s", tx1.Value)
	}
	// Alice is the sender — her own nonce should be preserved (baseFromLevel is Full)
	if tx1.Nonce == nil || *tx1.Nonce != 5 {
		t.Errorf("tx1: Sender's own nonce should be preserved, got %v", tx1.Nonce)
	}

	// tx2: Alice is NOT participant, Bob should be hidden
	tx2 := result[1]
	if tx2.Hash != "0x02" {
		t.Fatalf("expected tx2 hash 0x02, got %s", tx2.Hash)
	}
	if *tx2.To != "[PRIVATE]" {
		t.Errorf("tx2: To should be [PRIVATE] (non-participant), got %s", *tx2.To)
	}
	if tx2.Value != "" {
		t.Errorf("tx2: Value should be stripped (one side hidden, non-participant), got %s", tx2.Value)
	}
	// Carol's nonce should be preserved — Carol is Full (public sender), only Bob is hidden
	// The nonce strip only applies when the SENDER is hidden, not the receiver
	if tx2.Nonce == nil || *tx2.Nonce != 8 {
		t.Errorf("tx2: Carol's nonce should be preserved (sender is public), got %v", tx2.Nonce)
	}
}
