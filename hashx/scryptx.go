package hashx

import (
	"crypto/rand"
	"github.com/nuntiodev/x/cryptox"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/scrypt"
)

// Some constants used throughout the code
const (
	N                = 16384
	r                = 8
	p                = 1
	metadataLenBytes = 60
	saltLenBytes     = 16
)

type scryptx struct{}

func NewScrypt() Hashx {
	return &scryptx{}
}

func generateSalt() ([]byte, error) {
	salt := make([]byte, saltLenBytes)
	_, err := rand.Read(salt)
	if err != nil {
		return nil, err
	}
	return salt, nil
}

func (h *scryptx) CreateHash(code string) (string, error) {
	salt, err := cryptox.GenerateSymmetricKey(32, cryptox.AlphaNum)
	if err != nil {
		return "", err
	}
	//https://github.com/agnivade/easy-scrypt/blob/88dceb2547a14794232f2cb1f17ffaa71ab108c5/scrypt.go#L131
	/*
		Firebase:
		hash_config {
		  algorithm: SCRYPT,
		  base64_signer_key: jxspr8Ki0RYycVU8zykbdLGjFQ3McFUH0uiiTvC8pVMXAn210wjLNmdZJzxUECKbm0QsEmYUSDzZvpjeJ9WmXA==,
		  base64_salt_separator: Bw==,
		  rounds: 8,
		  mem_cost: 14,
		}
	*/
	scrypt.Key([]byte(code), []byte(salt), 1<<15, 8, 1, 32)
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	return string(hash), err
}

func (h *scryptx) CompareHashCode(hash, code string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(code))
}
