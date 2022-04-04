package cryptox

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

/*
TestEncryptDecrypt generates all allowed keys and encrypts/decrypts the plaintext and makes sure the result is the same.
*/
func TestEncryptDecrypt(t *testing.T) {
	plaintext := "SomeVeryLongPlainTextWithSp€cialCharsAndNumb3rs"
	c, err := New()
	assert.NoError(t, err)
	for runes, _ := range allowedRunes {
		// generate key
		key, err := c.GenerateSymmetricKey(32, runes)
		assert.NoError(t, err)
		assert.NotEmpty(t, key)
		// encrypt
		ciphertext, err := c.Encrypt(plaintext, key)
		assert.NoError(t, err)
		assert.NotEqual(t, plaintext, ciphertext)
		// decrypt
		decryptedCiphertext, err := c.Decrypt(ciphertext, key)
		assert.NoError(t, err)
		assert.Equal(t, plaintext, decryptedCiphertext)
	}
}

func TestEncryptDecryptWithCombinedKeys(t *testing.T) {
	plaintext := "SomeVeryLongPlainTextWithSp€cialCharsAndNumb3rs"
	c, err := New()
	// combine 3 keys into
	keyOne, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	keyTwo, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	keyThree, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	key, err := c.CombineSymmetricKeys([]string{keyOne, keyTwo, keyThree})
	assert.NoError(t, err)
	// encrypt
	ciphertext, err := c.Encrypt(plaintext, key)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)
	// decrypt
	decryptedCiphertext, err := c.Decrypt(ciphertext, key)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decryptedCiphertext)
}

func TestEncryptNoKey(t *testing.T) {
	plaintext := "SomeVeryLongPlainTextWithSp€cialCharsAndNumb3rs"
	c, err := New()
	assert.NoError(t, err)
	// encrypt
	ciphertext, err := c.Encrypt(plaintext, "")
	assert.Error(t, err)
	assert.NotEqual(t, plaintext, ciphertext)
}

func TestDecryptNoKey(t *testing.T) {
	plaintext := "SomeVeryLongPlainTextWithSp€cialCharsAndNumb3rs"
	c, err := New()
	// generate key
	key, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	assert.NotEmpty(t, key)
	// encrypt
	ciphertext, err := c.Encrypt(plaintext, key)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)
	// decrypt
	decryptedCiphertext, err := c.Decrypt(ciphertext, "")
	assert.Error(t, err)
	assert.Empty(t, decryptedCiphertext)
}

func TestKeyGenInvalidRunes(t *testing.T) {
	c, err := New()
	key, err := c.GenerateSymmetricKey(0, 1000)
	assert.Error(t, err)
	assert.Empty(t, key)
}
