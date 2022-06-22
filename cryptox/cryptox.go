package cryptox

import (
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
	SetInternalEncryptionKeys(keys []string) error
	SetExternalEncryptionKeys(keys []string) error
	GetInternalEncryptionKeys() ([]string, string)
	GetExternalEncryptionKeys() ([]string, string)
}

type defaultCrypto struct {
	IKeys []string
	EKeys []string
	IKey  []byte
	EKey  []byte
}

func (c *defaultCrypto) SetInternalEncryptionKeys(keys []string) error {
	for index, key := range keys {
		if strings.TrimSpace(key) == "" {
			keys = append(keys[:index], keys[index+1:]...)
		}
	}
	iKey, err := CombineSymmetricKeys(keys, len(keys))
	if err != nil {
		return err
	}
	//Since the key is in string, we need to convert decode it to bytes
	internlKey, err := hex.DecodeString(iKey)
	if err != nil {
		return err
	}
	c.IKeys = keys
	c.IKey = internlKey
	return nil
}

func (c *defaultCrypto) SetExternalEncryptionKeys(keys []string) error {
	for index, key := range keys {
		if strings.TrimSpace(key) == "" {
			keys = append(keys[:index], keys[index+1:]...)
		}
	}
	eKey, err := CombineSymmetricKeys(keys, len(keys))
	if err != nil {
		return err
	}
	//Since the key is in string, we need to convert decode it to bytes
	externalKey, err := hex.DecodeString(eKey)
	if err != nil {
		return err
	}
	c.EKeys = keys
	c.EKey = externalKey
	return nil
}

func (c *defaultCrypto) GetInternalEncryptionKeys() ([]string, string) {
	return c.IKeys, string(c.IKey)
}

func (c *defaultCrypto) GetExternalEncryptionKeys() ([]string, string) {
	return c.EKeys, string(c.EKey)
}

func New(iKeys, eKeys []string) (Crypto, error) {
	for index, key := range iKeys {
		if strings.TrimSpace(key) == "" {
			iKeys = append(iKeys[:index], iKeys[index+1:]...)
		}
	}
	for index, key := range eKeys {
		if strings.TrimSpace(key) == "" {
			eKeys = append(eKeys[:index], eKeys[index+1:]...)
		}
	}
	c := &defaultCrypto{
		IKeys: iKeys,
		EKeys: eKeys,
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
		c.IKey = internlKey
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
		c.EKey = externalKey
	}
	return c, nil
}
