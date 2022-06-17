package hashx

import "golang.org/x/crypto/bcrypt"

type bcryptx struct{}

func NewBcrypt() Hashx {
	return &bcryptx{}
}

func (h *bcryptx) CreateHash(code string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(code), bcrypt.DefaultCost)
	return string(hash), err
}

func (h *bcryptx) CompareHashCode(hash, code string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(code))
}
