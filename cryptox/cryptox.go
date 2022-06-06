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
	SetInternalEncryptionKeys(keys []string) error
	SetExternalEncryptionKeys(keys []string) error
}

type Stringx struct {
	Body                    string `json:"body"`
	ExternalEncryptionLevel int32  `json:"external_encryption_level"`
	InternalEncryptionLevel int32  `json:"internal_encryption_level"`
}

type defaultCrypto struct {
	iKeys []string
	eKeys []string
	iKey  []byte
	eKey  []byte
}

func (c *defaultCrypto) SetInternalEncryptionKeys(keys []string) error {
	iKey, err := CombineSymmetricKeys(keys, len(keys))
	if err != nil {
		return err
	}
	//Since the key is in string, we need to convert decode it to bytes
	internlKey, err := hex.DecodeString(iKey)
	if err != nil {
		return err
	}
	c.iKeys = keys
	c.iKey = internlKey
	return nil
}

func (c *defaultCrypto) SetExternalEncryptionKeys(keys []string) error {
	eKey, err := CombineSymmetricKeys(keys, len(keys))
	if err != nil {
		return err
	}
	//Since the key is in string, we need to convert decode it to bytes
	externalKey, err := hex.DecodeString(eKey)
	if err != nil {
		return err
	}
	c.eKeys = keys
	c.eKey = externalKey
	return nil
}

func New(iKeys, eKeys []string) (Crypto, error) {
	c := &defaultCrypto{
		iKeys: iKeys,
		eKeys: eKeys,
	}
	if len(iKeys) > 0 {
		iKey, err := CombineSymmetricKeys(iKeys, len(iKeys))
		if err != nil {
			return nil, err
		}
		//Since the key is in string, we need to convert decode it to bytes
		internlKey, err := hex.DecodeString(iKey)
		if err != nil {
			return nil, err
		}
		c.iKey = internlKey
	}
	if len(eKeys) > 0 {
		eKey, err := CombineSymmetricKeys(eKeys, len(eKeys))
		if err != nil {
			return nil, err
		}
		//Since the key is in string, we need to convert decode it to bytes
		externalKey, err := hex.DecodeString(eKey)
		if err != nil {
			return nil, err
		}
		c.eKey = externalKey
	}
	return c, nil
}
