package cryptox

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

type InnerStruct struct {
	One Stringx
	Two *Stringx
}

type ComplexStruct struct {
	One   string
	Two   int32
	Three *InnerStruct
	Four  *Stringx
	Five  Stringx
	Six   map[string]Stringx
	Seven map[string]*Stringx
}

/*
	TestEncryptDecrypt generates all allowed SymmetricKeys and encrypts/decrypts the plaintext and makes sure the result is the same.
*/
func TestEncryptDecrypt(t *testing.T) {
	for runes, _ := range allowedRunes {
		// generate internal key
		internalKey, err := GenerateSymmetricKey(32, runes)
		assert.NoError(t, err)
		assert.NotEmpty(t, internalKey)
		// generate external key
		externalKey, err := GenerateSymmetricKey(32, runes)
		assert.NoError(t, err)
		assert.NotEmpty(t, externalKey)
		// generate public key
		s, p, err := GenerateRsaKeyPair(2048)
		assert.NoError(t, err)
		// setup cryptox
		c, err := New([]string{internalKey}, p, s)
		assert.NoError(t, err)
		// create complex struct to encrypt
		test1 := "Test 1"
		test2 := int32(2)
		heyo1 := "Heyo1"
		heyo2 := "Heyo2"
		heyo3 := "Heyo3"
		heyo4 := "Heyo4"
		heyo6 := map[string]Stringx{
			"one": {Body: "Test 1234"},
			"two": {Body: "Test 12345"},
		}
		heyo7 := map[string]*Stringx{
			"three": {Body: "Test 123456"},
			"four":  {Body: "Test 1234567"},
		}
		complexStruct := &ComplexStruct{
			One: test1,
			Two: test2,
			Three: &InnerStruct{
				One: Stringx{Body: heyo1},
				Two: &Stringx{Body: heyo2},
			},
			Four: &Stringx{Body: heyo3},
			Five: Stringx{Body: heyo4},
			Six: map[string]Stringx{
				"one": {Body: "Test 1234"},
				"two": {Body: "Test 12345"},
			},
			Seven: map[string]*Stringx{
				"three": {Body: "Test 123456"},
				"four":  {Body: "Test 1234567"},
			},
		}
		// encrypt
		assert.NoError(t, c.Encrypt(complexStruct))
		// assert not equal to original one
		assert.Equal(t, test1, complexStruct.One)
		assert.Equal(t, test2, complexStruct.Two)
		assert.NotEqual(t, heyo1, complexStruct.Three.One.Body)
		assert.NotEqual(t, heyo2, complexStruct.Three.Two.Body)
		assert.NotEqual(t, heyo3, complexStruct.Four.Body)
		assert.NotEqual(t, heyo4, complexStruct.Five.Body)
		assert.False(t, reflect.DeepEqual(heyo6, complexStruct.Six), heyo6)
		assert.False(t, reflect.DeepEqual(heyo7, complexStruct.Seven))
		assert.Equal(t, int32(1), complexStruct.Three.One.EncryptionLevel)
		assert.Equal(t, int32(1), complexStruct.Three.Two.EncryptionLevel)
		assert.Equal(t, int32(1), complexStruct.Four.EncryptionLevel)
		assert.Equal(t, int32(1), complexStruct.Five.EncryptionLevel)
		// decrypt
		// insert new external and external key
		upgradable, err := c.Upgradeble(complexStruct)
		assert.NoError(t, err)
		assert.False(t, upgradable)
		key, err := GenerateSymmetricKey(32, runes)
		assert.NoError(t, err)
		assert.NoError(t, c.SetSymmetricEncryptionKeys([]string{internalKey, key}))
		assert.NoError(t, err)
		assert.NoError(t, c.Decrypt(complexStruct))
		assert.Equal(t, test1, complexStruct.One)
		assert.Equal(t, test2, complexStruct.Two)
		assert.Equal(t, heyo1, complexStruct.Three.One.Body)
		assert.Equal(t, heyo2, complexStruct.Three.Two.Body)
		assert.Equal(t, heyo3, complexStruct.Four.Body)
		assert.Equal(t, heyo4, complexStruct.Five.Body)
		for key, val := range complexStruct.Six {
			assert.Equal(t, heyo6[key].Body, val.Body)
		}
		for key, val := range complexStruct.Seven {
			assert.Equal(t, heyo7[key].Body, val.Body)
		}
		// encrypt again with and check that level is upgraded
		upgradable, err = c.Upgradeble(complexStruct)
		assert.NoError(t, err)
		assert.True(t, upgradable)
		assert.NoError(t, c.Encrypt(complexStruct))
		assert.Equal(t, test1, complexStruct.One)
		assert.Equal(t, test2, complexStruct.Two)
		assert.NotEqual(t, heyo1, complexStruct.Three.One.Body)
		assert.NotEqual(t, heyo2, complexStruct.Three.Two.Body)
		assert.NotEqual(t, heyo3, complexStruct.Four.Body)
		assert.NotEqual(t, heyo4, complexStruct.Five.Body)
		assert.Equal(t, int32(2), complexStruct.Three.One.EncryptionLevel)
		assert.Equal(t, int32(2), complexStruct.Three.Two.EncryptionLevel)
		assert.Equal(t, int32(2), complexStruct.Four.EncryptionLevel)
		assert.Equal(t, int32(2), complexStruct.Five.EncryptionLevel)
	}
}

func TestEncryptDecryptOnlyInternal(t *testing.T) {
	for runes, _ := range allowedRunes {
		// generate internal key
		internalKey, err := GenerateSymmetricKey(32, runes)
		assert.NoError(t, err)
		assert.NotEmpty(t, internalKey)
		// setup cryptox
		c, err := New([]string{internalKey}, nil, nil)
		assert.NoError(t, err)
		// create complex struct to encrypt
		test1 := "Test 1"
		test2 := int32(2)
		heyo1 := "Heyo1"
		heyo3 := "Heyo3"
		heyo4 := "Heyo4"
		complexStruct := &ComplexStruct{
			One: test1,
			Two: test2,
			Three: &InnerStruct{
				One: Stringx{Body: heyo1},
				Two: nil,
			},
			Four: &Stringx{Body: heyo3},
			Five: Stringx{Body: heyo4},
		}
		// encrypt
		assert.NoError(t, c.Encrypt(complexStruct))
		// assert not equal to original one
		assert.Equal(t, test1, complexStruct.One)
		assert.Equal(t, test2, complexStruct.Two)
		assert.NotEqual(t, heyo1, complexStruct.Three.One.Body)
		assert.Equal(t, "", complexStruct.Three.Two.Body)
		assert.NotEqual(t, heyo3, complexStruct.Four.Body)
		assert.NotEqual(t, heyo4, complexStruct.Five.Body)
		assert.Equal(t, int32(1), complexStruct.Three.One.EncryptionLevel)
		assert.Equal(t, int32(0), complexStruct.Three.Two.EncryptionLevel)
		assert.Equal(t, int32(1), complexStruct.Four.EncryptionLevel)
		assert.Equal(t, int32(1), complexStruct.Five.EncryptionLevel)
		// decrypt
		// insert new external and external key
		upgradable, err := c.Upgradeble(complexStruct)
		assert.NoError(t, err)
		assert.False(t, upgradable)
		key, err := GenerateSymmetricKey(32, runes)
		assert.NoError(t, err)
		assert.NoError(t, c.SetSymmetricEncryptionKeys([]string{internalKey, key}))
		assert.NoError(t, err)
		assert.NoError(t, c.Decrypt(complexStruct))
		assert.Equal(t, test1, complexStruct.One)
		assert.Equal(t, test2, complexStruct.Two)
		assert.Equal(t, heyo1, complexStruct.Three.One.Body)
		assert.Equal(t, "", complexStruct.Three.Two.Body)
		assert.Equal(t, heyo3, complexStruct.Four.Body)
		assert.Equal(t, heyo4, complexStruct.Five.Body)
		// encrypt again with and check that level is upgraded
		upgradable, err = c.Upgradeble(complexStruct)
		assert.NoError(t, err)
		assert.True(t, upgradable)
		assert.NoError(t, c.Encrypt(complexStruct))
		assert.Equal(t, test1, complexStruct.One)
		assert.Equal(t, test2, complexStruct.Two)
		assert.NotEqual(t, heyo1, complexStruct.Three.One.Body)
		assert.Equal(t, "", complexStruct.Three.Two.Body)
		assert.NotEqual(t, heyo3, complexStruct.Four.Body)
		assert.NotEqual(t, heyo4, complexStruct.Five.Body)
		assert.Equal(t, int32(2), complexStruct.Three.One.EncryptionLevel)
		assert.Equal(t, int32(0), complexStruct.Three.Two.EncryptionLevel)
		assert.Equal(t, int32(2), complexStruct.Four.EncryptionLevel)
		assert.Equal(t, int32(2), complexStruct.Five.EncryptionLevel)
		// test get encryption level
		internal, external := c.EncryptionLevel(complexStruct)
		assert.Equal(t, int32(2), internal)
		assert.Equal(t, int32(0), external)
	}
}

/*
	TestEncryptDecryptNoSymmetricKeys makes sure we do not throw an errror when encrypting/decrypting without SymmetricKeys
*/
func TestEncryptDecryptNoSymmetricKeys(t *testing.T) {
	// setup cryptox
	c, err := New([]string{}, nil, nil)
	assert.NoError(t, err)
	// create complex struct to encrypt
	test1 := "Test 1"
	test2 := int32(2)
	heyo1 := "Heyo1"
	heyo2 := "Heyo2"
	heyo3 := "Heyo3"
	heyo4 := "Heyo4"
	complexStruct := &ComplexStruct{
		One: test1,
		Two: test2,
		Three: &InnerStruct{
			One: Stringx{Body: heyo1},
			Two: &Stringx{Body: heyo2},
		},
		Four: &Stringx{Body: heyo3},
		Five: Stringx{Body: heyo4},
	}
	// encrypt
	assert.NoError(t, c.Encrypt(complexStruct))
	// assert not equal to original one
	assert.Equal(t, test1, complexStruct.One)
	assert.Equal(t, test2, complexStruct.Two)
	assert.Equal(t, heyo1, complexStruct.Three.One.Body)
	assert.Equal(t, heyo2, complexStruct.Three.Two.Body)
	assert.Equal(t, heyo3, complexStruct.Four.Body)
	assert.Equal(t, heyo4, complexStruct.Five.Body)
	assert.Equal(t, int32(0), complexStruct.Three.One.EncryptionLevel)
	assert.Equal(t, int32(0), complexStruct.Three.Two.EncryptionLevel)
	assert.Equal(t, int32(0), complexStruct.Four.EncryptionLevel)
	assert.Equal(t, int32(0), complexStruct.Five.EncryptionLevel)
	// decrypt
	// insert new external and external key
	upgradable, err := c.Upgradeble(complexStruct)
	assert.NoError(t, err)
	assert.False(t, upgradable)
	key, err := GenerateSymmetricKey(32, AlphaLowerNum)
	assert.NoError(t, err)
	assert.NoError(t, c.SetSymmetricEncryptionKeys([]string{key}))
	assert.NoError(t, err)
	assert.NoError(t, c.Decrypt(complexStruct))
	assert.Equal(t, test1, complexStruct.One)
	assert.Equal(t, test2, complexStruct.Two)
	assert.Equal(t, heyo1, complexStruct.Three.One.Body)
	assert.Equal(t, heyo2, complexStruct.Three.Two.Body)
	assert.Equal(t, heyo3, complexStruct.Four.Body)
	assert.Equal(t, heyo4, complexStruct.Five.Body)
	// encrypt again with and check that level is upgraded
	upgradable, err = c.Upgradeble(complexStruct)
	assert.NoError(t, err)
	assert.True(t, upgradable)
	assert.NoError(t, c.Encrypt(complexStruct))
	assert.Equal(t, test1, complexStruct.One)
	assert.Equal(t, test2, complexStruct.Two)
	assert.NotEqual(t, heyo1, complexStruct.Three.One.Body)
	assert.NotEqual(t, heyo2, complexStruct.Three.Two.Body)
	assert.NotEqual(t, heyo3, complexStruct.Four.Body)
	assert.NotEqual(t, heyo4, complexStruct.Five.Body)
	assert.Equal(t, int32(1), complexStruct.Three.One.EncryptionLevel)
	assert.Equal(t, int32(1), complexStruct.Three.Two.EncryptionLevel)
	assert.Equal(t, int32(1), complexStruct.Four.EncryptionLevel)
	assert.Equal(t, int32(1), complexStruct.Five.EncryptionLevel)
}

/*
func TestInvalidEncryptionLevel(t *testing.T) {
	c, err := New()
	keyOne, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	key, err := c.CombineSymmetricSymmetricKeys([]string{keyOne}, 2)
	assert.Error(t, err)
	assert.Empty(t, key)
}

func TestEncryptDecryptWithCombinedSymmetricKeys(t *testing.T) {
	plaintext := "SomeVeryLongPlainTextWithSp???cialCharsAndNumb3rs"
	c, err := New()
	// create 4 encryption SymmetricKeys
	keyOne, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	keyTwo, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	keyThree, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	keyFour, err := c.GenerateSymmetricKey(32, AlphaNum)
	assert.NoError(t, err)
	// combine the first 3 encryption SymmetricKeys into a new encryption key
	key, err := c.CombineSymmetricSymmetricKeys([]string{keyOne, keyTwo, keyThree, keyFour}, 3)
	assert.NoError(t, err)
	// encrypt
	ciphertext, err := c.Encrypt(plaintext, key)
	assert.NoError(t, err)
	assert.NotEqual(t, plaintext, ciphertext)
	// decrypt - make sure we can generate the same key and decrypt
	key, err = c.CombineSymmetricSymmetricKeys([]string{keyOne, keyTwo, keyThree, keyFour}, 3)
	assert.NoError(t, err)
	decryptedCiphertext, err := c.Decrypt(ciphertext, key)
	assert.NoError(t, err)
	assert.Equal(t, plaintext, decryptedCiphertext)
}

func TestEncryptNoKey(t *testing.T) {
	plaintext := "SomeVeryLongPlainTextWithSp???cialCharsAndNumb3rs"
	c, err := New()
	assert.NoError(t, err)
	// encrypt
	ciphertext, err := c.Encrypt(plaintext, "")
	assert.Error(t, err)
	assert.NotEqual(t, plaintext, ciphertext)
}

func TestDecryptNoKey(t *testing.T) {
	plaintext := "SomeVeryLongPlainTextWithSp???cialCharsAndNumb3rs"
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
*/
