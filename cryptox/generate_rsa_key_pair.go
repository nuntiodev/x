package cryptox

import (
	"crypto/rand"
	"crypto/rsa"
)

func GenerateRsaKeyPair(length int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, length)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}
