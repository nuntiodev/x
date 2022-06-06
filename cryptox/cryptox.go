package cryptox

import (
	"encoding/hex"
	"encoding/json"
)

const (
	TokenTypeAccess  = "access_token"
	TokenTypeRefresh = "refresh_token"
	Issuer           = "Block User Service"
)

type Crypto interface {
	Encrypt(enc interface{}) error
	Decrypt(dec interface{}) error
}

type Stringx struct {
	Body                    string `json:"body"`
	ExternalEncryptionLevel int32  `json:"external_encryption_level"`
	InternalEncryptionLevel int32  `json:"internal_encryption_level"`
}

func (s *Stringx) Marshal() ([]byte, error) {
	return json.Marshal(s)
}

func Unmarshal(s []byte) (*Stringx, error) {
	var resp Stringx
	err := json.Unmarshal(s, &resp)
	return &resp, err
}

type defaultCrypto struct {
	iKeys []string
	eKeys []string
	iKey  []byte
	eKey  []byte
}

func New(iKeys, eKeys []string) (Crypto, error) {
	c := &defaultCrypto{
		iKeys: iKeys,
		eKeys: eKeys,
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
	c.iKey = internlKey
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
	return c, nil
}
