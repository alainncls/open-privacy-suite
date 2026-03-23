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

func TestRedactTransactions_BothRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 txs (both redacted → drop), got %d", len(result))
	}
}

func TestRedactTransactions_HiddenPlusRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 txs (hidden + redacted → drop), got %d", len(result))
	}
}

func TestRedactTransactions_RedactedPlusFull_Keeps(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityFull,
	})

	txs := []Transaction{{Hash: "0x01", From: from, To: strPtr(to), Value: "1000", InputData: "0xdeadbeef"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (redacted + full → keep), got %d", len(result))
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

func TestRedactTransfers_BothRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "100"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 transfers (both redacted → drop), got %d", len(result))
	}
}

func TestRedactTransfers_HiddenPlusRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	transfers := []TokenTransfer{{ID: 1, From: from, To: to, Value: "100"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 transfers (hidden + redacted → drop), got %d", len(result))
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

func TestRedactInternalTransactions_BothRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityRedacted,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "100"}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 (both redacted → drop), got %d", len(result))
	}
}

func TestRedactInternalTransactions_HiddenPlusRedacted_Drops(t *testing.T) {
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityHidden,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityRedacted,
	})

	itxs := []InternalTransaction{{ID: 1, From: from, To: strPtr(to), Value: "100"}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected 0 (hidden + redacted → drop), got %d", len(result))
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
// RedactLogs — participant override
// ---------------------------------------------------------------------------

func TestRedactLogs_ParticipantOverride_SeeOwnLogs(t *testing.T) {
	// Eve's EOA calls a private contract. The contract emits a log.
	// Without participant override: log dropped (contract is Redacted).
	// With participant override: log visible (Eve is the tx sender).
	contractAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	eveAddr := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	topic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		contractAddr: VisibilityRedacted,
	}, []string{eveAddr})

	logs := []Log{{
		ID: 1, Address: contractAddr, TxHash: "0xabc",
		Topic0: &topic0, Data: "0x0000000000000000000000000000000000000000000000000000000002faf080",
	}}

	// Without participant context — log should be stripped (topics/data nil)
	result, err := engine.RedactLogs(context.Background(), logs, "did:test:eve")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log (redacted), got %d", len(result))
	}
	if result[0].Topic0 != nil {
		t.Error("without participant context, topic0 should be nil")
	}
	if result[0].Data != "" {
		t.Error("without participant context, data should be stripped")
	}

	// With participant context (Eve is the tx sender) — log should be fully visible
	result, err = engine.RedactLogs(context.Background(), logs, "did:test:eve", eveAddr, contractAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 log, got %d", len(result))
	}
	if result[0].Topic0 == nil || *result[0].Topic0 != topic0 {
		t.Errorf("with participant override, topic0 should be preserved, got %v", result[0].Topic0)
	}
	if result[0].Data == "" {
		t.Error("with participant override, data should be preserved")
	}
}

func TestRedactLogs_ParticipantOverride_NonParticipantStillRedacted(t *testing.T) {
	// Mallory is NOT a participant in the tx (different address from from/to).
	// Even though she passes participant addresses, her linked address doesn't match.
	contractAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	senderAddr := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	malloryAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	topic0 := "0xddf252ad"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		contractAddr: VisibilityRedacted,
	}, []string{malloryAddr})

	logs := []Log{{ID: 1, Address: contractAddr, Topic0: &topic0, Data: "0xdata"}}

	// participantAddrs are from the parent tx (sender → contract).
	// Mallory's linked addr (0xbbbb...) does NOT match sender (0xeeee...) or contract.
	result, err := engine.RedactLogs(context.Background(), logs, "did:test:mallory", senderAddr, contractAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Topic0 != nil {
		t.Error("non-participant should still get redacted logs (topics stripped)")
	}
	if result[0].Data != "" {
		t.Error("non-participant should still get redacted logs (data stripped)")
	}
}

func TestRedactLogs_ParticipantOverride_HiddenStillDropped(t *testing.T) {
	// Even with participant override, Hidden logs should stay dropped.
	// (Hidden = completely invisible, not just redacted)
	contractAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	eveAddr := "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
	topic0 := "0xddf252ad"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		contractAddr: VisibilityHidden,
	}, []string{eveAddr})

	logs := []Log{{ID: 1, Address: contractAddr, Topic0: &topic0, Data: "0xdata"}}

	result, err := engine.RedactLogs(context.Background(), logs, "did:test:eve", eveAddr, contractAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("Hidden logs should still be dropped even with participant override, got %d", len(result))
	}
}

// ---------------------------------------------------------------------------
// RedactLogs — comprehensive visibility matrix
// ---------------------------------------------------------------------------

func TestRedactLogs_VisibilityMatrix(t *testing.T) {
	// Addresses
	publicContract := "0x1111111111111111111111111111111111111111"
	redactedContract := "0x2222222222222222222222222222222222222222"
	hiddenContract := "0x3333333333333333333333333333333333333333"
	aliceAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // tx sender
	bobAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"   // tx receiver
	malloryAddr := "0xcccccccccccccccccccccccccccccccccccccccc" // not a participant

	topic0 := "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
	data := "0x00000000000000000000000000000000000000000000000000000000deadbeef"

	// 3 logs from 3 contracts with different visibility
	makeLogs := func() []Log {
		return []Log{
			{ID: 1, Address: publicContract, TxHash: "0xtx1", Topic0: &topic0, Data: data},
			{ID: 2, Address: redactedContract, TxHash: "0xtx1", Topic0: &topic0, Data: data},
			{ID: 3, Address: hiddenContract, TxHash: "0xtx1", Topic0: &topic0, Data: data},
		}
	}

	visMap := VisibilityMap{
		publicContract:   VisibilityFull,
		redactedContract: VisibilityRedacted,
		hiddenContract:   VisibilityHidden,
	}

	// parent tx: alice → bob
	parentFrom := aliceAddr
	parentTo := bobAddr

	type expect struct {
		count         int    // number of logs returned
		publicTopic   bool   // public contract log has topic0
		redactedTopic bool   // redacted contract log has topic0 (if present)
		redactedAddr  string // redacted contract address in result
	}

	cases := []struct {
		name             string
		viewerDID        string
		linkedAddrs      []string
		participantAddrs []string
		expect           expect
	}{
		{
			name:             "anonymous, no participant context",
			viewerDID:        "",
			linkedAddrs:      nil,
			participantAddrs: nil,
			expect:           expect{count: 2, publicTopic: true, redactedTopic: false, redactedAddr: "[PRIVATE]"},
			// public: visible. redacted: kept but stripped. hidden: dropped.
		},
		{
			name:             "anonymous, with participant addrs (should not help)",
			viewerDID:        "",
			linkedAddrs:      nil,
			participantAddrs: []string{parentFrom, parentTo},
			expect:           expect{count: 2, publicTopic: true, redactedTopic: false, redactedAddr: "[PRIVATE]"},
			// anonymous has no linked addrs → can't match participant addrs
		},
		{
			name:             "alice (sender), no participant context",
			viewerDID:        "did:test:alice",
			linkedAddrs:      []string{aliceAddr},
			participantAddrs: nil,
			expect:           expect{count: 2, publicTopic: true, redactedTopic: false, redactedAddr: "[PRIVATE]"},
			// without participant addrs, can't know alice is the sender
		},
		{
			name:             "alice (sender), with participant context",
			viewerDID:        "did:test:alice",
			linkedAddrs:      []string{aliceAddr},
			participantAddrs: []string{parentFrom, parentTo},
			expect:           expect{count: 2, publicTopic: true, redactedTopic: true, redactedAddr: redactedContract},
			// alice's linked addr matches parentFrom → participant override fires
			// redacted contract upgraded to Full: topics/data preserved, address shown
			// hidden still dropped
		},
		{
			name:             "bob (receiver), with participant context",
			viewerDID:        "did:test:bob",
			linkedAddrs:      []string{bobAddr},
			participantAddrs: []string{parentFrom, parentTo},
			expect:           expect{count: 2, publicTopic: true, redactedTopic: true, redactedAddr: redactedContract},
			// bob's linked addr matches parentTo → participant override fires
		},
		{
			name:             "mallory (non-participant), with participant context",
			viewerDID:        "did:test:mallory",
			linkedAddrs:      []string{malloryAddr},
			participantAddrs: []string{parentFrom, parentTo},
			expect:           expect{count: 2, publicTopic: true, redactedTopic: false, redactedAddr: "[PRIVATE]"},
			// mallory's linked addr doesn't match from or to → no override
		},
		{
			name:        "admin (contract is Full for them)",
			viewerDID:   "did:test:admin",
			linkedAddrs: nil,
			// Admin sees the contract as Full via GetBatchVisibility, not via participant override
			// We simulate this by using a different visMap below
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.name == "admin (contract is Full for them)" {
				// Admin has Full on all contracts
				adminVisMap := VisibilityMap{
					publicContract:   VisibilityFull,
					redactedContract: VisibilityFull,
					hiddenContract:   VisibilityFull,
				}
				adminEngine := newEngine(adminVisMap)
				logs := makeLogs()
				result, err := adminEngine.RedactLogs(context.Background(), logs, tc.viewerDID)
				if err != nil {
					t.Fatal(err)
				}
				if len(result) != 3 {
					t.Fatalf("admin should see all 3 logs, got %d", len(result))
				}
				for _, l := range result {
					if l.Topic0 == nil || *l.Topic0 != topic0 {
						t.Errorf("admin should see all topics, log %d topic0=%v", l.ID, l.Topic0)
					}
					if l.Data != data {
						t.Errorf("admin should see all data, log %d", l.ID)
					}
				}
				return
			}

			engine := newEngineWithLinkedAddrs(visMap, tc.linkedAddrs)
			logs := makeLogs()
			result, err := engine.RedactLogs(context.Background(), logs, tc.viewerDID, tc.participantAddrs...)
			if err != nil {
				t.Fatal(err)
			}

			if len(result) != tc.expect.count {
				t.Fatalf("expected %d logs, got %d", tc.expect.count, len(result))
			}

			for _, l := range result {
				switch strings.ToLower(l.Address) {
				case publicContract:
					if tc.expect.publicTopic && (l.Topic0 == nil || *l.Topic0 != topic0) {
						t.Error("public contract log should have topic0 preserved")
					}
					if l.Data != data {
						t.Error("public contract log data should be preserved")
					}
				case "[private]":
					// This is the redacted contract (address replaced)
					if l.Address != tc.expect.redactedAddr {
						t.Errorf("redacted contract address: expected %s, got %s", tc.expect.redactedAddr, l.Address)
					}
					if tc.expect.redactedTopic {
						t.Error("redacted log with [PRIVATE] address should not have topics (this case shouldn't happen)")
					}
					if l.Topic0 != nil {
						t.Error("redacted log should have nil topic0")
					}
					if l.Data != "" {
						t.Error("redacted log should have empty data")
					}
				case redactedContract:
					// Participant override: contract address is shown, topics preserved
					if !tc.expect.redactedTopic {
						t.Error("unexpected: redacted contract shown with real address without participant override")
					}
					if l.Topic0 == nil || *l.Topic0 != topic0 {
						t.Error("participant override should preserve topic0")
					}
					if l.Data != data {
						t.Error("participant override should preserve data")
					}
				case hiddenContract:
					t.Error("hidden contract log should never appear in results")
				default:
					// Could be a pseudonym — check it's not the hidden contract
					if l.Address == hiddenContract {
						t.Error("hidden contract should be dropped")
					}
				}
			}
		})
	}
}

func TestRedactLogs_MultipleContractsMixedVisibility(t *testing.T) {
	// A tx triggers logs from 4 different contracts.
	// Viewer is a participant. Tests that override applies per-tx, not per-contract.
	userAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	fullContract := "0x1111111111111111111111111111111111111111"
	redactedA := "0x2222222222222222222222222222222222222222"
	redactedB := "0x3333333333333333333333333333333333333333"
	hiddenContract := "0x4444444444444444444444444444444444444444"

	topic0 := "0xabcdef"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		fullContract:   VisibilityFull,
		redactedA:      VisibilityRedacted,
		redactedB:      VisibilityRedacted,
		hiddenContract: VisibilityHidden,
	}, []string{userAddr})

	logs := []Log{
		{ID: 1, Address: fullContract, Topic0: &topic0, Data: "0xfull"},
		{ID: 2, Address: redactedA, Topic0: &topic0, Data: "0xredA"},
		{ID: 3, Address: redactedB, Topic0: &topic0, Data: "0xredB"},
		{ID: 4, Address: hiddenContract, Topic0: &topic0, Data: "0xhidden"},
	}

	// With participant context: user is the tx sender
	result, err := engine.RedactLogs(context.Background(), logs, "did:test:user", userAddr, redactedA)
	if err != nil {
		t.Fatal(err)
	}

	// Expected: full(1) + redactedA(2, upgraded) + redactedB(3, upgraded) + hidden(4, dropped) = 3
	if len(result) != 3 {
		t.Fatalf("expected 3 logs (hidden dropped), got %d", len(result))
	}

	for _, l := range result {
		if l.Topic0 == nil {
			t.Errorf("log %d: topic0 should be preserved (all non-hidden get participant override)", l.ID)
		}
		if l.Data == "" {
			t.Errorf("log %d: data should be preserved", l.ID)
		}
		if l.Address == hiddenContract {
			t.Error("hidden contract log should not appear")
		}
	}
}

func TestRedactLogs_ParticipantIsReceiver(t *testing.T) {
	// The viewer is the TO of the parent tx (receiving a transfer).
	// Contract emits a Transfer log. Viewer should see it.
	contractAddr := "0x2222222222222222222222222222222222222222"
	senderAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	receiverAddr := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	topic0 := "0xddf252ad"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		contractAddr: VisibilityRedacted,
	}, []string{receiverAddr})

	logs := []Log{{ID: 1, Address: contractAddr, Topic0: &topic0, Data: "0xdata"}}

	result, err := engine.RedactLogs(context.Background(), logs, "did:test:receiver", senderAddr, receiverAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Topic0 == nil || *result[0].Topic0 != topic0 {
		t.Error("receiver participant should see topic0")
	}
	if result[0].Data != "0xdata" {
		t.Error("receiver participant should see data")
	}
}

func TestRedactLogs_NoLinkedAddresses(t *testing.T) {
	// Authenticated user with no linked ETH addresses. Even with participant
	// context, they can't be a participant because they have no addresses.
	contractAddr := "0x2222222222222222222222222222222222222222"
	senderAddr := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	topic0 := "0xddf252ad"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		contractAddr: VisibilityRedacted,
	}, nil) // no linked addresses

	logs := []Log{{ID: 1, Address: contractAddr, Topic0: &topic0, Data: "0xdata"}}

	result, err := engine.RedactLogs(context.Background(), logs, "did:test:noaddr", senderAddr, contractAddr)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1, got %d", len(result))
	}
	if result[0].Topic0 != nil {
		t.Error("user with no linked addresses should not get participant override")
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

// ---------------------------------------------------------------------------
// RedactTransfers — Participant visibility override
// ---------------------------------------------------------------------------

func TestRedactTransfers_ParticipantSeesCounterparty_Sender(t *testing.T) {
	// Alice (viewer) is the sender (From). Bob (To) is hidden globally,
	// but Alice should see Bob's address and the transfer value because
	// Alice is a participant.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityFull,
		bob:   VisibilityHidden,
	}, []string{alice})

	transfers := []TokenTransfer{{ID: 1, From: alice, To: bob, Value: "750"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer, got %d", len(result))
	}
	tr := result[0]
	if tr.From != alice {
		t.Errorf("From should be unchanged, got %s", tr.From)
	}
	if tr.To != bob {
		t.Errorf("To should be Bob's real address (participant visibility), got %s", tr.To)
	}
	if tr.Value != "750" {
		t.Errorf("Value should be preserved for participant, got %s", tr.Value)
	}
}

func TestRedactTransfers_ParticipantSeesCounterparty_Receiver(t *testing.T) {
	// Bob (viewer) is the receiver (To). Alice (From) is hidden globally,
	// but Bob should see Alice's address and the transfer value because
	// Bob is a participant.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{bob})

	transfers := []TokenTransfer{{ID: 1, From: alice, To: bob, Value: "300"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer, got %d", len(result))
	}
	tr := result[0]
	if tr.From != alice {
		t.Errorf("From should be Alice's real address (participant visibility), got %s", tr.From)
	}
	if tr.To != bob {
		t.Errorf("To should be unchanged, got %s", tr.To)
	}
	if tr.Value != "300" {
		t.Errorf("Value should be preserved for participant, got %s", tr.Value)
	}
}

func TestRedactTransfers_NonParticipantDoesNotSeeHiddenTransfer(t *testing.T) {
	// Charlie (viewer) is not a participant. Alice (From) is hidden.
	// Charlie should see [PRIVATE] for Alice and Value should be stripped.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	charlie := "0xcccccccccccccccccccccccccccccccccccccccc"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{charlie})

	transfers := []TokenTransfer{{ID: 1, From: alice, To: bob, Value: "500"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:charlie")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer, got %d", len(result))
	}
	tr := result[0]
	if tr.From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE] for non-participant, got %s", tr.From)
	}
	if tr.To != bob {
		t.Errorf("To should be unchanged, got %s", tr.To)
	}
	if tr.Value != "" {
		t.Errorf("Value should be stripped (one side hidden, non-participant), got %s", tr.Value)
	}
}

func TestRedactTransfers_ParticipantBothHidden_StillVisible(t *testing.T) {
	// Alice (viewer) is the sender (From). Both Alice and Bob are hidden
	// in the visibility map. With participant override, both should become
	// visible and the transfer should be kept with value preserved.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityHidden,
	}, []string{alice})

	transfers := []TokenTransfer{{ID: 1, From: alice, To: bob, Value: "1000"}}
	result, err := engine.RedactTransfers(context.Background(), transfers, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 transfer (participant override prevents drop), got %d", len(result))
	}
	tr := result[0]
	if tr.From != alice {
		t.Errorf("From should be Alice's real address (participant visibility), got %s", tr.From)
	}
	if tr.To != bob {
		t.Errorf("To should be Bob's real address (participant visibility), got %s", tr.To)
	}
	if tr.Value != "1000" {
		t.Errorf("Value should be preserved for participant, got %s", tr.Value)
	}
}

// ---------------------------------------------------------------------------
// RedactInternalTransactions — Participant visibility override
// ---------------------------------------------------------------------------

func TestRedactInternalTransactions_ParticipantSeesCounterparty_Sender(t *testing.T) {
	// Alice (viewer) is From. Bob (To) is hidden globally, but Alice
	// should see Bob's address and all data because Alice is a participant.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := "0xdeadbeef"
	output := "0x01"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityFull,
		bob:   VisibilityHidden,
	}, []string{alice})

	itxs := []InternalTransaction{{ID: 1, From: alice, To: strPtr(bob), Value: "400", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 internal tx, got %d", len(result))
	}
	itx := result[0]
	if itx.From != alice {
		t.Errorf("From should be unchanged, got %s", itx.From)
	}
	if *itx.To != bob {
		t.Errorf("To should be Bob's real address (participant visibility), got %s", *itx.To)
	}
	if itx.Value != "400" {
		t.Errorf("Value should be preserved for participant, got %s", itx.Value)
	}
	if itx.Input == nil || *itx.Input != "0xdeadbeef" {
		t.Errorf("Input should be preserved for participant, got %v", itx.Input)
	}
	if itx.Output == nil || *itx.Output != "0x01" {
		t.Errorf("Output should be preserved for participant, got %v", itx.Output)
	}
}

func TestRedactInternalTransactions_ParticipantSeesCounterparty_Receiver(t *testing.T) {
	// Bob (viewer) is To. Alice (From) is hidden globally, but Bob
	// should see Alice's address and all data because Bob is a participant.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	input := "0xcafebabe"
	output := "0xff"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{bob})

	itxs := []InternalTransaction{{ID: 1, From: alice, To: strPtr(bob), Value: "600", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:bob")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 internal tx, got %d", len(result))
	}
	itx := result[0]
	if itx.From != alice {
		t.Errorf("From should be Alice's real address (participant visibility), got %s", itx.From)
	}
	if *itx.To != bob {
		t.Errorf("To should be unchanged, got %s", *itx.To)
	}
	if itx.Value != "600" {
		t.Errorf("Value should be preserved for participant, got %s", itx.Value)
	}
	if itx.Input == nil || *itx.Input != "0xcafebabe" {
		t.Errorf("Input should be preserved for participant, got %v", itx.Input)
	}
	if itx.Output == nil || *itx.Output != "0xff" {
		t.Errorf("Output should be preserved for participant, got %v", itx.Output)
	}
}

func TestRedactInternalTransactions_NonParticipantDoesNotSeeHidden(t *testing.T) {
	// Charlie (viewer) is not a participant. Alice (From) is hidden.
	// Charlie should see [PRIVATE] for Alice, Value stripped, Input/Output nil.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	charlie := "0xcccccccccccccccccccccccccccccccccccccccc"
	input := "0xdeadbeef"
	output := "0x01"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice: VisibilityHidden,
		bob:   VisibilityFull,
	}, []string{charlie})

	itxs := []InternalTransaction{{ID: 1, From: alice, To: strPtr(bob), Value: "250", Input: &input, Output: &output}}
	result, err := engine.RedactInternalTransactions(context.Background(), itxs, "did:charlie")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 internal tx, got %d", len(result))
	}
	itx := result[0]
	if itx.From != "[PRIVATE]" {
		t.Errorf("From should be [PRIVATE] for non-participant, got %s", itx.From)
	}
	if *itx.To != bob {
		t.Errorf("To should be unchanged, got %s", *itx.To)
	}
	if itx.Value != "" {
		t.Errorf("Value should be stripped (one side hidden, non-participant), got %s", itx.Value)
	}
	if itx.Input != nil {
		t.Errorf("Input should be nil for non-participant with hidden side")
	}
	if itx.Output != nil {
		t.Errorf("Output should be nil for non-participant with hidden side")
	}
}

// TestRedactTransactions_AnonymousViewerContractCreationScenario reproduces the
// exact bug: an anonymous user (Eve) sees 53 transactions including contract
// creations from org-owned deployers. After the fix, contract creations from
// hidden deployers are dropped.
func TestRedactTransactions_AnonymousViewerContractCreationScenario(t *testing.T) {
	orgDeployerAddr := "0xdeployer000000000000000000000000000000"
	publicEOA1 := "0xpublic1000000000000000000000000000000000"
	publicEOA2 := "0xpublic2000000000000000000000000000000000"

	db := &mockDB{
		visMap: VisibilityMap{
			orgDeployerAddr: VisibilityHidden, // org-owned, hidden from Eve
			publicEOA1:      VisibilityFull,    // public address
			publicEOA2:      VisibilityFull,    // public address
		},
	}
	engine := NewRedactionEngine(nil, db)

	to1 := publicEOA2
	txs := []Transaction{
		// Contract creation from org deployer — should be DROPPED
		{Hash: "0xdeploy1", From: orgDeployerAddr, To: nil},
		{Hash: "0xdeploy2", From: orgDeployerAddr, To: nil},
		{Hash: "0xdeploy3", From: orgDeployerAddr, To: nil},
		// Normal transfer between public addresses — should be KEPT
		{Hash: "0xtransfer1", From: publicEOA1, To: &to1},
	}

	result, err := engine.RedactTransactions(context.Background(), txs, "") // anonymous viewer
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected 1 visible tx (the public transfer), got %d", len(result))
	}
	if len(result) > 0 && result[0].Hash != "0xtransfer1" {
		t.Errorf("expected the public transfer to survive, got hash=%s", result[0].Hash)
	}
}

// TestRedactTransactions_ContractCreationHiddenDeployer verifies that contract
// creation transactions from a hidden deployer are dropped entirely.
// This prevents leaking deployment activity, timing, and contract addresses.
func TestRedactTransactions_ContractCreationHiddenDeployer(t *testing.T) {
	deployerAddr := "0xdeployer000000000000000000000000000000"

	db := &mockDB{
		visMap: VisibilityMap{
			deployerAddr: VisibilityHidden,
		},
	}
	engine := NewRedactionEngine(nil, db)

	txs := []Transaction{
		{
			Hash: "0xdeploy1",
			From: deployerAddr,
			To:   nil, // contract creation
		},
	}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:eve")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected contract creation from hidden deployer to be dropped, got %d transactions", len(result))
	}
}

// TestRedactTransactions_ContractCreationVisibleDeployer verifies that contract
// creation transactions from a visible deployer are kept.
func TestRedactTransactions_ContractCreationVisibleDeployer(t *testing.T) {
	deployerAddr := "0xdeployer000000000000000000000000000000"

	db := &mockDB{
		visMap: VisibilityMap{
			deployerAddr: VisibilityFull,
		},
	}
	engine := NewRedactionEngine(nil, db)

	txs := []Transaction{
		{
			Hash: "0xdeploy1",
			From: deployerAddr,
			To:   nil,
		},
	}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:alice")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 1 {
		t.Errorf("expected visible deployer's contract creation to be kept, got %d", len(result))
	}
}

// TestRedactTransactions_ContractCreationRedactedDeployer verifies that redacted
// (not just hidden) deployers also get their contract creations dropped.
func TestRedactTransactions_ContractCreationRedactedDeployer(t *testing.T) {
	deployerAddr := "0xdeployer000000000000000000000000000000"

	db := &mockDB{
		visMap: VisibilityMap{
			deployerAddr: VisibilityRedacted,
		},
	}
	engine := NewRedactionEngine(nil, db)

	txs := []Transaction{
		{
			Hash: "0xdeploy1",
			From: deployerAddr,
			To:   nil,
		},
	}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:eve")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected contract creation from redacted deployer to be dropped, got %d", len(result))
	}
}
