package cryptox

import (
	"encoding/hex"
	"errors"
	"fmt"
)

func CombineSymmetricSymmetricKeys(SymmetricKeys []string, level int) (string, error) {
	if len(SymmetricKeys) == 0 {
		return "", errors.New("invalid number of SymmetricKeys 0")
	} else if level > len(SymmetricKeys) {
		return "", errors.New("level cannot be larger than amount of encryption SymmetricKeys")
	} else if level <= 0 {
		return "", errors.New("level cannot be less than 0")
	}
	if len(SymmetricKeys) == 1 && level == 1 {
		return SymmetricKeys[0], nil
	}
	// validate length is the same
	key, err := hex.DecodeString(SymmetricKeys[0])
	if err != nil {
		return "", err
	}
	initialKey := string(key)
	for i := 1; i < level; i++ {
		if len(SymmetricKeys[i]) != 64 {
			return "", fmt.Errorf("invalid key size: %d", len(SymmetricKeys[i]))
		}
		key, err := hex.DecodeString(SymmetricKeys[i])
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

// todo: make some distribution over SymmetricKeys to validate randomness
