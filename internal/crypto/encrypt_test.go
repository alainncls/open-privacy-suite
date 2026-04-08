package crypto

import (
	"crypto/rand"
	"testing"
)

func TestEncryptDecryptRoundtrip(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		plaintext string
	}{
		{"simple", "sk-live-abc123"},
		{"empty", ""},
		{"long", "this-is-a-very-long-api-key-that-contains-many-characters-1234567890"},
		{"special chars", "key!@#$%^&*()_+-=[]{}|;':\",./<>?"},
		{"unicode", "key-\u00e9\u00e8\u00ea"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encrypted, err := Encrypt(tt.plaintext, key)
			if err != nil {
				t.Fatalf("Encrypt() error: %v", err)
			}

			// Encrypted value should differ from plaintext (unless empty)
			if tt.plaintext != "" && encrypted == tt.plaintext {
				t.Error("encrypted value should differ from plaintext")
			}

			decrypted, err := Decrypt(encrypted, key)
			if err != nil {
				t.Fatalf("Decrypt() error: %v", err)
			}

			if decrypted != tt.plaintext {
				t.Errorf("roundtrip failed: got %q, want %q", decrypted, tt.plaintext)
			}
		})
	}
}

func TestEmptyKeyPassthrough(t *testing.T) {
	plaintext := "sk-live-abc123"

	encrypted, err := Encrypt(plaintext, nil)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}
	if encrypted != plaintext {
		t.Errorf("empty key should passthrough: got %q, want %q", encrypted, plaintext)
	}

	decrypted, err := Decrypt(encrypted, nil)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}
	if decrypted != plaintext {
		t.Errorf("empty key should passthrough: got %q, want %q", decrypted, plaintext)
	}
}

func TestWrongKeyReturnsEncoded(t *testing.T) {
	key1 := make([]byte, 32)
	key2 := make([]byte, 32)
	if _, err := rand.Read(key1); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(key2); err != nil {
		t.Fatal(err)
	}

	plaintext := "sk-live-abc123"

	encrypted, err := Encrypt(plaintext, key1)
	if err != nil {
		t.Fatalf("Encrypt() error: %v", err)
	}

	// Decrypting with wrong key should return the encoded string (graceful fallback)
	decrypted, err := Decrypt(encrypted, key2)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	// Should return the encoded string, not panic or error
	if decrypted != encrypted {
		t.Errorf("wrong key should return encoded string: got %q, want %q", decrypted, encrypted)
	}
}

func TestLegacyPlaintextDecryption(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	// A plaintext value that is not valid base64 should be returned as-is
	legacyPlaintext := "sk-live-abc123!@#"

	decrypted, err := Decrypt(legacyPlaintext, key)
	if err != nil {
		t.Fatalf("Decrypt() error: %v", err)
	}

	if decrypted != legacyPlaintext {
		t.Errorf("legacy plaintext should passthrough: got %q, want %q", decrypted, legacyPlaintext)
	}
}

func TestInvalidKeyLength(t *testing.T) {
	shortKey := make([]byte, 16) // AES-128, not AES-256

	_, err := Encrypt("test", shortKey)
	if err == nil {
		t.Error("Encrypt() should reject non-32-byte key")
	}

	_, err = Decrypt("test", shortKey)
	if err == nil {
		t.Error("Decrypt() should reject non-32-byte key")
	}
}

func TestEncryptProducesDifferentCiphertexts(t *testing.T) {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	plaintext := "sk-live-abc123"

	enc1, _ := Encrypt(plaintext, key)
	enc2, _ := Encrypt(plaintext, key)

	if enc1 == enc2 {
		t.Error("encrypting same plaintext twice should produce different ciphertexts (random nonce)")
	}

	// Both should decrypt to the same plaintext
	dec1, _ := Decrypt(enc1, key)
	dec2, _ := Decrypt(enc2, key)

	if dec1 != plaintext || dec2 != plaintext {
		t.Error("both ciphertexts should decrypt to the original plaintext")
	}
}
