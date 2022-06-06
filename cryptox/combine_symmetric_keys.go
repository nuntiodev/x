package cryptox

import (
	"encoding/hex"
	"errors"
	"fmt"
)

func CombineSymmetricKeys(keys []string, level int) (string, error) {
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
	key, err := hex.DecodeString(keys[0])
	if err != nil {
		return "", err
	}
	initialKey := string(key)
	for i := 1; i < level; i++ {
		if len(keys[i]) != 64 {
			return "", fmt.Errorf("invalid key size: %d", len(keys[i]))
		}
		key, err := hex.DecodeString(keys[i])
		if err != nil {
			return "", err
		}
		currentKey := string(key)
		newKey := []byte{}
		for j := range initialKey {
			newKey = append(newKey, initialKey[j]^currentKey[j])
		}
		initialKey = string(newKey)
	}
	newKey := hex.EncodeToString([]byte(initialKey))
	if len(newKey) != 64 {
		return "", fmt.Errorf("invalid length: %d", len(newKey))
	}
	return newKey, nil
}

// todo: make some distribution over keys to validate randomness
