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

func (m *mockDB) GetBatchVisibilityDetailed(_ context.Context, _ string, _ []string) (map[string]AddressVisibility, error) {
	if m.err != nil {
		return nil, m.err
	}
	res := make(map[string]AddressVisibility)
	for k, v := range m.visMap {
		reason := ReasonPublicAddress
		switch v {
		case VisibilityFull:
			reason = ReasonPublicAddress
		case VisibilityHidden, VisibilityRedacted:
			reason = ReasonNoAccess
		case VisibilityPseudonymous:
			reason = ReasonRBACGroupMember
		}
		res[k] = AddressVisibility{Level: v, Reason: reason}
	}
	return res, nil
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

func TestRedactTransactions_HiddenFrom_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side hidden → dropped
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
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: hidden from, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_HiddenTo_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side hidden → dropped
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
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: hidden to, non-participant → drop), got %d", len(result))
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

func TestRedactTransactions_RedactedPlusFull_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side redacted → dropped
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
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: redacted from, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_HiddenFrom_PublicTo_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side hidden → dropped
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
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: hidden from, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_HiddenTo_PublicFrom_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side hidden → dropped
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
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: hidden to, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_RedactedFrom_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side redacted → dropped
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
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: redacted from, non-participant → drop), got %d", len(result))
	}
}

func TestRedactTransactions_RedactedTo_DroppedForNonParticipant(t *testing.T) {
	// G10: non-participant, one side redacted → dropped
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
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: redacted to, non-participant → drop), got %d", len(result))
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
	// G10: non-participant txs with any hidden/redacted side are dropped.
	// Only Full<->Full survives for non-participants.
	addrFull := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addrHidden := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	addrRedacted := "0xcccccccccccccccccccccccccccccccccccccccc"
	engine := newEngine(VisibilityMap{
		"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa": VisibilityFull,
		"0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb": VisibilityHidden,
		"0xcccccccccccccccccccccccccccccccccccccccc": VisibilityRedacted,
	})

	txs := []Transaction{
		{Hash: "0x01", From: addrFull, To: strPtr(addrFull)},       // keep (both Full)
		{Hash: "0x02", From: addrFull, To: strPtr(addrHidden)},     // drop (G10: hidden to, non-participant)
		{Hash: "0x03", From: addrFull, To: strPtr(addrRedacted)},   // drop (G10: redacted to, non-participant)
		{Hash: "0x04", From: addrHidden, To: strPtr(addrFull)},     // drop (G10: hidden from, non-participant)
		{Hash: "0x05", From: addrHidden, To: strPtr(addrHidden)},   // drop (both hidden)
	}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (only 0x01 Full<->Full survives), got %d", len(result))
	}
	if result[0].Hash != "0x01" {
		t.Errorf("surviving tx should be 0x01, got %s", result[0].Hash)
	}
}

// ---------------------------------------------------------------------------
// Nonce redaction
// ---------------------------------------------------------------------------

func u64ptr(n uint64) *uint64 { return &n }

func TestRedactTransactions_HiddenFrom_NilsNonce(t *testing.T) {
	// Viewer is the receiver (participant), sender is hidden.
	// Nonce of hidden sender must be nil even when revealed via participant override.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		from: VisibilityHidden,
		to:   VisibilityFull,
	}, []string{to}) // viewer is the receiver

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
		t.Errorf("nonce must be nil when sender is base-hidden (participant override), got %v", *result[0].Nonce)
	}
}

func TestRedactTransactions_HiddenTo_PreservesNonce(t *testing.T) {
	// Viewer is the sender (participant). Receiver is hidden.
	// Sender's own nonce should be preserved (their base level is Full).
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		from: VisibilityFull,
		to:   VisibilityHidden,
	}, []string{from}) // viewer is the sender

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
		t.Errorf("nonce should be preserved when sender (viewer) is Full, got %v", result[0].Nonce)
	}
}

func TestRedactTransactions_RedactedFrom_NilsNonce(t *testing.T) {
	// Viewer is the receiver (participant). Sender is redacted.
	// Nonce of redacted sender must be nil even via participant override.
	from := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	to := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	engine := newEngineWithLinkedAddrs(VisibilityMap{
		from: VisibilityRedacted,
		to:   VisibilityFull,
	}, []string{to}) // viewer is the receiver

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
		t.Errorf("nonce must be nil when sender is base-redacted, got %v", *result[0].Nonce)
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
	// G10: Charlie (viewer) is not a participant. Alice is hidden.
	// Under G10, the tx is dropped entirely for non-participants.
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
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: non-participant, hidden from → drop), got %d", len(result))
	}
}

func TestRedactTransactions_ParticipantVisibilityDoesNotLeakToOtherTxs(t *testing.T) {
	// Alice (viewer) is participant in tx1 (Alice -> Bob) but NOT in tx2 (Carol -> Bob).
	// Bob is hidden globally. Under G10, tx2 is dropped (non-participant, hidden to).
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
		{Hash: "0x02", From: carol, To: strPtr(bob), Value: "200", Nonce: nonce8},  // Alice is NOT participant → dropped (G10)
	}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (tx2 dropped under G10), got %d", len(result))
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
}

// ---------------------------------------------------------------------------
// Calldata-level participant detection — ERC20 transfer recipients
// ---------------------------------------------------------------------------

func TestRedactTransactions_CalldataParticipant_ERC20Transfer(t *testing.T) {
	// Alice sends ERC20 transfer to Dave via contract. Tx-level to = contract.
	// Dave's address is in the calldata (transfer(address,uint256)).
	// Dave should be detected as participant and see Alice's address + value.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dave := "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
	contract := "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9"

	// transfer(address,uint256) selector = 0xa9059cbb
	// Dave's address padded to 32 bytes + amount
	calldata := "0xa9059cbb00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice:    VisibilityHidden,
		dave:     VisibilityFull,
		contract: VisibilityFull,
	}, []string{dave})

	contractStr := contract
	nonce := uint64(5)
	txs := []Transaction{{
		Hash:      "0x01",
		From:      alice,
		To:        &contractStr,
		Value:     "1000",
		InputData: calldata,
		Nonce:     &nonce,
	}}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:dave")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (Dave is calldata participant), got %d", len(result))
	}

	// Dave should see Alice's real address (participant override)
	if result[0].From != alice {
		t.Errorf("expected From=%s (participant sees counterparty), got %s", alice, result[0].From)
	}
	// Value should be preserved (participant sees value)
	if result[0].Value == "0" || result[0].Value == "" {
		t.Errorf("expected value preserved for participant, got %q", result[0].Value)
	}
}

func TestRedactTransactions_CalldataParticipant_TransferFrom(t *testing.T) {
	// transferFrom(alice, dave, amount) — Dave is param 1 (to)
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dave := "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
	contract := "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9"

	// transferFrom(address,address,uint256) selector = 0x23b872dd
	calldata := "0x23b872dd000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice:    VisibilityHidden,
		dave:     VisibilityFull,
		contract: VisibilityFull,
	}, []string{dave})

	contractStr := contract
	txs := []Transaction{{
		Hash:      "0x02",
		From:      "0xspender", // spender is a third party
		To:        &contractStr,
		Value:     "500",
		InputData: calldata,
	}}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:dave")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (Dave is transferFrom recipient), got %d", len(result))
	}
}

func TestRedactTransactions_CalldataParticipant_NonParticipantStillHidden(t *testing.T) {
	// G10: Charlie is NOT in the calldata or tx-level from/to.
	// Alice (from) is hidden. Under G10, dropped for non-participant Charlie.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dave := "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
	charlie := "0x90f79bf6eb2c4f870365e785982e1f101e93b906"
	contract := "0xcf7ed3acca5a467e9e704c703e8d87f634fb0fc9"

	calldata := "0xa9059cbb00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000"

	engine := newEngineWithLinkedAddrs(VisibilityMap{
		alice:    VisibilityHidden,
		dave:     VisibilityHidden,
		charlie:  VisibilityFull,
		contract: VisibilityFull,
	}, []string{charlie})

	contractStr := contract
	txs := []Transaction{{
		Hash:      "0x03",
		From:      alice,
		To:        &contractStr,
		Value:     "1000",
		InputData: calldata,
	}}

	result, err := engine.RedactTransactions(context.Background(), txs, "did:test:charlie")
	if err != nil {
		t.Fatal(err)
	}

	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: non-participant, hidden from → drop), got %d", len(result))
	}
}

func TestIsViewerInCalldata(t *testing.T) {
	dave := "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
	addrs := map[string]bool{dave: true}

	tests := []struct {
		name      string
		inputData string
		expect    bool
	}{
		{"ERC20 transfer to viewer", "0xa9059cbb00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000", true},
		{"ERC20 transfer to someone else", "0xa9059cbb000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000056bc75e2d63100000", false},
		{"transferFrom with viewer as to", "0x23b872dd000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000", true},
		{"transferFrom with viewer as from", "0x23b872dd00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a65000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa0000000000000000000000000000000000000000000000056bc75e2d63100000", true},
		{"approve with viewer as spender", "0x095ea7b300000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000", true},
		{"ERC20 transfer no 0x prefix (DB format)", "a9059cbb00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000", true},
		{"unknown selector", "0xdeadbeef00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a65", false},
		{"empty input", "0x", false},
		{"too short", "0xa9059cbb", false},
		{"no input", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isViewerInCalldata(tt.inputData, addrs)
			if got != tt.expect {
				t.Errorf("isViewerInCalldata(%s) = %v, want %v", tt.name, got, tt.expect)
			}
		})
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

// ---------------------------------------------------------------------------
// AddressMetadata tests — verify the metadata map is populated with the correct
// visibility reason for each address in redacted transactions.
// ---------------------------------------------------------------------------

// mockDBDetailed is a mock that allows injecting specific AddressVisibility
// entries with fine-grained reasons (own_address, rbac_group_member, etc.).
type mockDBDetailed struct {
	visMap      VisibilityMap
	detailedMap map[string]AddressVisibility
	linkedAddrs []string
	err         error
}

func (m *mockDBDetailed) GetBatchVisibility(_ context.Context, _ string, _ []string) (VisibilityMap, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.visMap, nil
}

func (m *mockDBDetailed) GetBatchVisibilityDetailed(_ context.Context, _ string, _ []string) (map[string]AddressVisibility, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.detailedMap, nil
}

func (m *mockDBDetailed) GetLinkedAddresses(_ context.Context, _ string) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.linkedAddrs, nil
}

func newEngineDetailed(visMap VisibilityMap, detailedMap map[string]AddressVisibility, linkedAddrs []string) *RedactionEngine {
	return &RedactionEngine{store: nil, db: &mockDBDetailed{
		visMap:      visMap,
		detailedMap: detailedMap,
		linkedAddrs: linkedAddrs,
	}}
}

func TestRedactTransactions_AddressMetadata_OwnAddress(t *testing.T) {
	// When the viewer owns an address (own_address reason), the metadata should
	// reflect that.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityFull, bob: VisibilityFull},
		map[string]AddressVisibility{
			alice: {Level: VisibilityFull, Reason: ReasonOwnAddress},
			bob:   {Level: VisibilityFull, Reason: ReasonPublicAddress},
		},
		nil,
	)

	txs := []Transaction{{Hash: "0x01", From: alice, To: strPtr(bob), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].AddressMetadata == nil {
		t.Fatal("AddressMetadata should not be nil")
	}
	if result[0].AddressMetadata[alice] != ReasonOwnAddress {
		t.Errorf("expected own_address for alice, got %q", result[0].AddressMetadata[alice])
	}
	if result[0].AddressMetadata[bob] != ReasonPublicAddress {
		t.Errorf("expected public_address for bob, got %q", result[0].AddressMetadata[bob])
	}
}

func TestRedactTransactions_AddressMetadata_RBACGroupMember(t *testing.T) {
	// A contract granted via RBAC group membership should have rbac_group_member reason.
	viewer := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xcccccccccccccccccccccccccccccccccccccccc"

	engine := newEngineDetailed(
		VisibilityMap{viewer: VisibilityFull, contract: VisibilityFull},
		map[string]AddressVisibility{
			viewer:   {Level: VisibilityFull, Reason: ReasonOwnAddress},
			contract: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		nil,
	)

	txs := []Transaction{{Hash: "0x01", From: viewer, To: strPtr(contract), Value: "500"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:viewer")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].AddressMetadata[contract] != ReasonRBACGroupMember {
		t.Errorf("expected rbac_group_member for contract, got %q", result[0].AddressMetadata[contract])
	}
}

func TestRedactTransactions_AddressMetadata_ParticipantOverride(t *testing.T) {
	// When the viewer is a participant and the counterparty is base-level hidden,
	// the metadata should show participant_override for the counterparty.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityFull, bob: VisibilityHidden},
		map[string]AddressVisibility{
			alice: {Level: VisibilityFull, Reason: ReasonOwnAddress},
			bob:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
		},
		[]string{alice}, // alice is linked to the viewer
	)

	txs := []Transaction{{Hash: "0x01", From: alice, To: strPtr(bob), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	// Alice should see Bob's real address (participant override)
	if *result[0].To != bob {
		t.Errorf("expected Bob's real address via participant override, got %s", *result[0].To)
	}
	// Bob's metadata reason should be participant_override, not no_access
	if result[0].AddressMetadata[bob] != ReasonParticipantOverride {
		t.Errorf("expected participant_override for Bob, got %q", result[0].AddressMetadata[bob])
	}
	// Alice's metadata should still show own_address
	if result[0].AddressMetadata[alice] != ReasonOwnAddress {
		t.Errorf("expected own_address for Alice, got %q", result[0].AddressMetadata[alice])
	}
}

func TestRedactTransactions_AddressMetadata_NoAccess(t *testing.T) {
	// G10: When one side is hidden and the viewer is NOT a participant,
	// the tx is dropped entirely (not shown with [PRIVATE]).
	viewer := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hidden := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{viewer: VisibilityFull, hidden: VisibilityHidden},
		map[string]AddressVisibility{
			viewer: {Level: VisibilityFull, Reason: ReasonPublicAddress},
			hidden: {Level: VisibilityHidden, Reason: ReasonNoAccess},
		},
		nil, // no linked addresses — viewer is NOT a participant
	)

	txs := []Transaction{{Hash: "0x01", From: viewer, To: strPtr(hidden), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:outsider")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Fatalf("expected 0 txs (G10: non-participant, hidden to → drop), got %d", len(result))
	}
}

func TestRedactTransactions_AddressMetadata_DisclosureGrant(t *testing.T) {
	// When an address is visible via a disclosure grant, the metadata should
	// reflect disclosure_grant as the reason.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	disclosed := "0xdddddddddddddddddddddddddddddddddddddd"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityFull, disclosed: VisibilityFull},
		map[string]AddressVisibility{
			alice:     {Level: VisibilityFull, Reason: ReasonOwnAddress},
			disclosed: {Level: VisibilityFull, Reason: ReasonDisclosureGrant},
		},
		nil,
	)

	txs := []Transaction{{Hash: "0x01", From: alice, To: strPtr(disclosed), Value: "100"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].AddressMetadata[disclosed] != ReasonDisclosureGrant {
		t.Errorf("expected disclosure_grant for disclosed address, got %q", result[0].AddressMetadata[disclosed])
	}
}

func TestRedactTransactions_AddressMetadata_AlwaysPopulated(t *testing.T) {
	// Even for fully visible transactions, AddressMetadata should be non-nil and
	// contain entries for all involved addresses.
	addr1 := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	addr2 := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{addr1: VisibilityFull, addr2: VisibilityFull},
		map[string]AddressVisibility{
			addr1: {Level: VisibilityFull, Reason: ReasonOwnAddress},
			addr2: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		nil,
	)

	txs := []Transaction{{Hash: "0x01", From: addr1, To: strPtr(addr2), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:test")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	if result[0].AddressMetadata == nil {
		t.Fatal("AddressMetadata must not be nil for redacted transactions")
	}
	if len(result[0].AddressMetadata) != 2 {
		t.Errorf("expected 2 entries in AddressMetadata, got %d", len(result[0].AddressMetadata))
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

// ---------------------------------------------------------------------------
// visible_to_grant label tests
// ---------------------------------------------------------------------------

func TestRedactTransactions_VisibleToGrant_SetsMetadata(t *testing.T) {
	// A tx is in VisibleTxHashes and the from address is Hidden.
	// The viewer is NOT a participant but has the visibleTo grant.
	// Expected: metadata for the from address is "visible_to_grant".
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityHidden, bob: VisibilityFull},
		map[string]AddressVisibility{
			alice: {Level: VisibilityHidden, Reason: ReasonNoAccess},
			bob:   {Level: VisibilityFull, Reason: ReasonPublicAddress},
		},
		nil, // no linked addresses — viewer is NOT a participant
	)

	txs := []Transaction{{Hash: "0xabc", From: alice, To: strPtr(bob), Value: "1000"}}
	opts := RedactOpts{VisibleTxHashes: map[string]bool{"0xabc": true}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:viewer", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	// Alice's address should be revealed (visibleTo upgrade)
	if result[0].From != alice {
		t.Errorf("expected From=%s (visibleTo override), got %s", alice, result[0].From)
	}
	// Alice's metadata should be visible_to_grant
	if result[0].AddressMetadata[alice] != ReasonVisibleToGrant {
		t.Errorf("expected visible_to_grant for alice, got %q", result[0].AddressMetadata[alice])
	}
	// Bob's metadata should be public_address (from DB)
	if result[0].AddressMetadata[bob] != ReasonPublicAddress {
		t.Errorf("expected public_address for bob, got %q", result[0].AddressMetadata[bob])
	}
}

func TestRedactTransactions_VisibleToGrant_ParticipantTakesPrecedence(t *testing.T) {
	// Viewer is both a participant (sender) AND tx is in VisibleTxHashes.
	// participant_override should take precedence over visible_to_grant.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityFull, bob: VisibilityHidden},
		map[string]AddressVisibility{
			alice: {Level: VisibilityFull, Reason: ReasonOwnAddress},
			bob:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
		},
		[]string{alice}, // alice is the viewer's linked address
	)

	txs := []Transaction{{Hash: "0xabc", From: alice, To: strPtr(bob), Value: "1000"}}
	opts := RedactOpts{VisibleTxHashes: map[string]bool{"0xabc": true}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:alice", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx, got %d", len(result))
	}
	// Bob's metadata should be participant_override, NOT visible_to_grant
	if result[0].AddressMetadata[bob] != ReasonParticipantOverride {
		t.Errorf("expected participant_override for bob (participant beats visibleTo), got %q", result[0].AddressMetadata[bob])
	}
}

// ---------------------------------------------------------------------------
// G10 fix: non-participant drop tests
// ---------------------------------------------------------------------------

func TestRedactTransactions_G10_NonParticipantContractCallDropped(t *testing.T) {
	// from=Hidden, to=Full(contract), viewer not participant, not visibleTo.
	// G10 says: drop — the RPC layer would return null for this tx.
	sender := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{sender: VisibilityHidden, contract: VisibilityFull},
		map[string]AddressVisibility{
			sender:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
			contract: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		nil, // no linked addresses — viewer is NOT a participant
	)

	txs := []Transaction{{Hash: "0x01", From: sender, To: strPtr(contract), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:outsider")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 0 {
		t.Errorf("expected tx to be dropped (G10: non-participant, one side hidden), got %d", len(result))
	}
}

func TestRedactTransactions_G10_ParticipantStillSees(t *testing.T) {
	// Same setup as above, but the viewer is the sender → participant → kept.
	sender := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{sender: VisibilityHidden, contract: VisibilityFull},
		map[string]AddressVisibility{
			sender:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
			contract: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		[]string{sender}, // viewer IS the sender
	)

	txs := []Transaction{{Hash: "0x01", From: sender, To: strPtr(contract), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:sender")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (participant keeps it), got %d", len(result))
	}
	if result[0].From != sender {
		t.Errorf("expected From=%s (participant override), got %s", sender, result[0].From)
	}
}

func TestRedactTransactions_G10_VisibleToStillSees(t *testing.T) {
	// Same setup, but tx hash is in VisibleTxHashes → kept.
	sender := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	contract := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{sender: VisibilityHidden, contract: VisibilityFull},
		map[string]AddressVisibility{
			sender:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
			contract: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		nil, // viewer is NOT a participant
	)

	txs := []Transaction{{Hash: "0x01", From: sender, To: strPtr(contract), Value: "1000"}}
	opts := RedactOpts{VisibleTxHashes: map[string]bool{"0x01": true}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:viewer", opts)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (visibleTo override keeps it), got %d", len(result))
	}
}

func TestRedactTransactions_G10_BothFullStillVisible(t *testing.T) {
	// Both from and to are Full visibility, viewer is NOT a participant.
	// Both sides are identifiable → tx should NOT be dropped.
	alice := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	bob := "0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

	engine := newEngineDetailed(
		VisibilityMap{alice: VisibilityFull, bob: VisibilityFull},
		map[string]AddressVisibility{
			alice: {Level: VisibilityFull, Reason: ReasonPublicAddress},
			bob:   {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		nil, // no linked addresses — viewer is NOT a participant
	)

	txs := []Transaction{{Hash: "0x01", From: alice, To: strPtr(bob), Value: "1000"}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:outsider")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (both Full, no drop), got %d", len(result))
	}
	if result[0].From != alice {
		t.Errorf("expected From=%s, got %s", alice, result[0].From)
	}
	if *result[0].To != bob {
		t.Errorf("expected To=%s, got %s", bob, *result[0].To)
	}
}

func TestRedactTransactions_G10_CalldataParticipantStillSees(t *testing.T) {
	// Viewer is the ERC20 transfer recipient (in calldata, not tx-level to).
	// from=Hidden, to=contract(Full). Viewer is calldata participant → kept.
	sender := "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	dave := "0x15d34aaf54267db7d7c367839aaf71a00a2c6a65"
	contract := "0xcccccccccccccccccccccccccccccccccccccccc"

	// transfer(address,uint256) selector = 0xa9059cbb, Dave is param 0
	calldata := "0xa9059cbb00000000000000000000000015d34aaf54267db7d7c367839aaf71a00a2c6a650000000000000000000000000000000000000000000000056bc75e2d63100000"

	engine := newEngineDetailed(
		VisibilityMap{sender: VisibilityHidden, dave: VisibilityFull, contract: VisibilityFull},
		map[string]AddressVisibility{
			sender:   {Level: VisibilityHidden, Reason: ReasonNoAccess},
			dave:     {Level: VisibilityFull, Reason: ReasonOwnAddress},
			contract: {Level: VisibilityFull, Reason: ReasonRBACGroupMember},
		},
		[]string{dave}, // Dave is the viewer
	)

	contractStr := contract
	txs := []Transaction{{
		Hash:      "0x01",
		From:      sender,
		To:        &contractStr,
		Value:     "1000",
		InputData: calldata,
	}}
	result, err := engine.RedactTransactions(context.Background(), txs, "did:dave")
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 tx (calldata participant keeps it), got %d", len(result))
	}
	// Sender's address should be revealed via participant override
	if result[0].From != sender {
		t.Errorf("expected From=%s (participant override), got %s", sender, result[0].From)
	}
}
