package cryptox

import (
	"encoding/hex"
	"errors"
	"fmt"
)

func (c *defaultCrypto) CombineSymmetricKeys(keys []string) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("invalid number of keys 0")
	}
	// validate length is the same
	initialKey := keys[0]
	for i := 1; i < len(keys); i++ {
		key := keys[i]
		// perform the xor operation
		n := len(initialKey) / 2
		b := make([]byte, n)
		for i := 0; i < n; i++ {
			b[i] = initialKey[i] ^ key[i]
		}
		initialKey = string(b)
		fmt.Println(len(initialKey))
	}
	return hex.EncodeToString([]byte(initialKey)), nil
}
