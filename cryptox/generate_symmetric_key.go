package cryptox

import (
	"encoding/hex"
	"fmt"
	"math/rand"
)

const (
	AlphaNum = iota
	Alpha
	AlphaLowerNum
	AlphaUpperNum
	AlphaLower
	AlphaUpper
	Numeric
)

var (
	alphaNum      = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	alpha         = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	alphaLowerNum = []rune("abcdefghijklmnopqrstuvwxyz0123456789")
	alphaUpperNum = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	alphaLower    = []rune("abcdefghijklmnopqrstuvwxyz")
	alphaUpper    = []rune("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
	numeric       = []rune("0123456789")
	allowedRunes  = map[int][]rune{
		AlphaNum:      alphaNum,
		Alpha:         alpha,
		AlphaLowerNum: alphaLowerNum,
		AlphaUpperNum: alphaUpperNum,
		AlphaLower:    alphaLower,
		AlphaUpper:    alphaUpper,
		Numeric:       numeric,
	}
)

func (c *defaultCrypto) GenerateSymmetricKey(length int, runes int) (string, error) {
	runeSpecification, ok := allowedRunes[runes]
	if !ok {
		return "", fmt.Errorf("invalid runes not allowed %d", runes)
	}
	b := make([]rune, length)
	for i := range b {
		b[i] = runeSpecification[rand.Intn(len(runeSpecification))]
	}
	return hex.EncodeToString([]byte(string(b))), nil
}
