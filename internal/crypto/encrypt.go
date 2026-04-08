package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// Encrypt encrypts plaintext using AES-256-GCM with the given key.
// Returns base64-encoded ciphertext. If key is empty, returns plaintext as-is (dev mode).
func Encrypt(plaintext string, key []byte) (string, error) {
	if len(key) == 0 {
		return plaintext, nil
	}
	if len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes (AES-256)")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aesGCM.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts base64-encoded ciphertext using AES-256-GCM.
// If key is empty, returns ciphertext as-is (dev mode / unencrypted value).
func Decrypt(encoded string, key []byte) (string, error) {
	if len(key) == 0 {
		return encoded, nil
	}
	if len(key) != 32 {
		return "", errors.New("encryption key must be 32 bytes (AES-256)")
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		// Not base64 = not encrypted (legacy plaintext value)
		return encoded, nil
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()
	if len(ciphertext) < nonceSize {
		// Too short to be encrypted, treat as plaintext
		return encoded, nil
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		// Decryption failed — might be legacy plaintext
		return encoded, nil
	}

	return string(plaintext), nil
}
