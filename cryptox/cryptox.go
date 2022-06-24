package cryptox

import (
	"crypto/rsa"
	"encoding/hex"
	"strings"
)

const (
	TokenTypeAccess  = "access_token"
	TokenTypeRefresh = "refresh_token"
	Issuer           = "Block User Service"
)

type Crypto interface {
	Encrypt(enc interface{}) error
	Decrypt(dec interface{}) error
	SetZero(val interface{}) error
	Upgradeble(val interface{}) (bool, error)
	EncryptionLevel(val interface{}) (int32, int32)
	SetSymmetricEncryptionKeys(SymmetricKeys []string) error
	GetSymmetricEncryptionKeys() ([]string, string)
}

type Stringx struct {
	Body               string `json:"body"`
	EncryptionLevel    int32  `json:"encryption_level"`
	PublicKeyEncrypted bool   `json:"public_key_encrypted"`
}

type defaultCrypto struct {
	SymmetricKeys []string
	SymmetricKey  []byte
	PublicKey     *rsa.PublicKey
	PrivateKey    *rsa.PrivateKey
}

func (c *defaultCrypto) SetSymmetricEncryptionKeys(SymmetricKeys []string) error {
	for index, key := range SymmetricKeys {
		if strings.TrimSpace(key) == "" {
			SymmetricKeys = append(SymmetricKeys[:index], SymmetricKeys[index+1:]...)
		}
	}
	iKey, err := CombineSymmetricSymmetricKeys(SymmetricKeys, len(SymmetricKeys))
	if err != nil {
		return err
	}
	//Since the key is in string, we need to convert decode it to bytes
	internlKey, err := hex.DecodeString(iKey)
	if err != nil {
		return err
	}
	c.SymmetricKeys = SymmetricKeys
	c.SymmetricKey = internlKey
	return nil
}

func (c *defaultCrypto) GetSymmetricEncryptionKeys() ([]string, string) {
	return c.SymmetricKeys, string(c.SymmetricKey)
}

func New(symmetricKeys []string, publicKey *rsa.PublicKey, privateKey *rsa.PrivateKey) (Crypto, error) {
	for index, key := range symmetricKeys {
		if strings.TrimSpace(key) == "" {
			symmetricKeys = append(symmetricKeys[:index], symmetricKeys[index+1:]...)
		}
	}
	c := &defaultCrypto{
		SymmetricKeys: symmetricKeys,
		PublicKey:     publicKey,
		PrivateKey:    privateKey,
	}
	if len(symmetricKeys) > 0 {
		iKey, err := CombineSymmetricSymmetricKeys(symmetricKeys, len(symmetricKeys))
		if err != nil {
			return nil, err
		}
		//Since the key is in string, we need to convert decode it to bytes
		key, err := hex.DecodeString(iKey)
		if err != nil {
			return nil, err
		}
		c.SymmetricKey = key
	}
	return c, nil
}
