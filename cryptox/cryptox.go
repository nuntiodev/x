package cryptox

import (
	"crypto/rsa"
)

const (
	TokenTypeAccess  = "access_token"
	TokenTypeRefresh = "refresh_token"
	Issuer           = "Block User Service"
)

type Crypto interface {
	GenerateRsaKeyPair(length int) (*rsa.PrivateKey, *rsa.PublicKey, error)
	GenerateSymmetricKey(length int, runes int) (string, error)
	CombineSymmetricKeys(keys []string) (string, error)
	Encrypt(stringToEncrypt string, keyString string) (string, error)
	Decrypt(encryptedString string, keyString string) (string, error)
}

type defaultCrypto struct{}

func New() (Crypto, error) {
	return &defaultCrypto{}, nil
}
