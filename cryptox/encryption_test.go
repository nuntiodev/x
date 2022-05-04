package cryptox

import (
	"encoding/hex"
	"fmt"
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

func TestInvalidEncryptionLevel(t *testing.T) {
	c, err := New()
	keyOne, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	key, err := c.CombineSymmetricKeys([]string{keyOne}, 2)
	assert.Error(t, err)
	assert.Empty(t, key)
}

func TestEncryptDecryptWithCombinedKeys(t *testing.T) {
	plaintext := "SomeVeryLongPlainTextWithSp€cialCharsAndNumb3rs"
	c, err := New()
	// create 4 encryption keys
	keyOne, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	keyTwo, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	keyThree, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	keyFour, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	// combine the first 3 encryption keys into a new encryption key
	key, err := c.CombineSymmetricKeys([]string{keyOne, keyTwo, keyThree, keyFour}, 3)
	assert.NoError(t, err)
	// encrypt
	ciphertext, err := c.Encrypt(plaintext, key)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)
	// decrypt - make sure we can generate the same key and decrypt
	key, err = c.CombineSymmetricKeys([]string{keyOne, keyTwo, keyThree, keyFour}, 3)
	assert.NoError(t, err)
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

func TestGenerateNumberKey(t *testing.T) {
	c, err := New()
	key, err := c.GenerateSymmetricKey(Numeric, 6)
	assert.NoError(t, err)
	assert.NotEmpty(t, key)
	dec, err := hex.DecodeString(key)
	assert.NoError(t, err)
	fmt.Println(string(dec))
}
