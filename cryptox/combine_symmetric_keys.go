package cryptox

import (
	"encoding/hex"
	"errors"
	"fmt"
)

func (c *defaultCrypto) CombineSymmetricKeys(keys []string, level int) (string, error) {
	if len(keys) == 0 {
		return "", errors.New("invalid number of keys 0")
	} else if level > len(keys) {
		return "", errors.New("level cannot be larger than amount of encryption keys")
	} else if level <= 0 {
		return "", errors.New("level cannot be less than 0")
	}
	if len(keys) == 1 && level == 1 {
		return keys[0], nil
	}
	// validate length is the same
	initialKey := keys[0]
	for i := 1; i < level; i++ {
		if len(keys[i]) != 64 {
			return "", fmt.Errorf("invalid key size: %d", len(keys[i]))
		}
		key := keys[i]
		// perform the xor operation
		n := len(initialKey) / 2
		b := make([]byte, n)
		for i := 0; i < n; i++ {
			b[i] = initialKey[i] ^ key[i]
		}
		initialKey = string(b)
	}
	newKey := hex.EncodeToString([]byte(initialKey))
	if len(newKey) != 64 {
		return "", errors.New("invalid length: %d", len(newKey))
	}
	return newKey, nil
}
