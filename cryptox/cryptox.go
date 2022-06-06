package cryptox

import (
	"encoding/hex"
)

const (
	TokenTypeAccess  = "access_token"
	TokenTypeRefresh = "refresh_token"
	Issuer           = "Block User Service"
)

type Crypto interface {
	Encrypt(enc interface{}) error
	Decrypt(dec interface{}) error
	Upgradeble(val interface{}) (bool, error)
}

type Stringx struct {
	Body                    string `json:"body"`
	ExternalEncryptionLevel int32  `json:"external_encryption_level"`
	InternalEncryptionLevel int32  `json:"internal_encryption_level"`
}

type defaultCrypto struct {
	IKeys []string
	EKeys []string
	IKey  []byte
	EKey  []byte
}

func New(iKeys, eKeys []string) (Crypto, error) {
	c := &defaultCrypto{
		IKeys: iKeys,
		EKeys: eKeys,
	}
	iKey, err := CombineSymmetricKeys(iKeys, len(iKeys))
	if err != nil {
		return nil, err
	}
	//Since the key is in string, we need to convert decode it to bytes
	internlKey, err := hex.DecodeString(iKey)
	if err != nil {
		return nil, err
	}
	c.IKey = internlKey
	eKey, err := CombineSymmetricKeys(eKeys, len(eKeys))
	if err != nil {
		return nil, err
	}
	//Since the key is in string, we need to convert decode it to bytes
	externalKey, err := hex.DecodeString(eKey)
	if err != nil {
		return nil, err
	}
	c.EKey = externalKey
	return c, nil
}
