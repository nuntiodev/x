package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
)

func (c *defaultCrypto) Encrypt(enc interface{}) error {
	v := reflect.Indirect(reflect.ValueOf(enc))
	// todo: make this async
	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		// first check if type is struct -> encrypt children
		typePtrStringx := reflect.TypeOf(field.Interface()) == reflect.TypeOf(&Stringx{})
		typeStringx := reflect.TypeOf(field.Interface()) == reflect.TypeOf(Stringx{})
		if typePtrStringx || typeStringx {
			// we accept types of Stringx or ptr Stringx
			stringx := &Stringx{}
			bytes, err := json.Marshal(field.Interface())
			if err != nil {
				return err
			}
			if err := json.Unmarshal(bytes, stringx); err != nil {
				return err
			}
			// encrypt using internal keys
			if len(c.IKeys) > 0 && stringx.Body != "" {
				if err := c.encrypt(stringx, c.IKey); err != nil {
					return err
				}
				stringx.InternalEncryptionLevel = int32(len(c.IKeys))
			}
			// encrypt using external keys
			if len(c.EKeys) > 0 && stringx.Body != "" {
				if err := c.encrypt(stringx, c.EKey); err != nil {
					return err
				}
				stringx.ExternalEncryptionLevel = int32(len(c.EKeys))
			}
			// update value in interface with new value
			if typePtrStringx {
				field.Set(reflect.ValueOf(stringx))
			} else {
				field.Set(reflect.ValueOf(*stringx))
			}
		} else if reflect.Indirect(field).Kind() == reflect.Struct {
			//recursive encryption todo: find a faster way
			c.Encrypt(field.Interface()) // do not catch err
		}
	}
	return nil
}

func (c *defaultCrypto) encrypt(enc *Stringx, key []byte) error {
	if enc == nil {
		return errors.New("stringx is nil")
	}
	plaintext := []byte(enc.Body)
	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	//Create a new GCM - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	//https://golang.org/pkg/crypto/cipher/#NewGCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	//Create a nonce. Nonce should be from GCM
	nonce := make([]byte, aesGCM.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return err
	}
	//WithEncryption the data using aesGCM.Seal
	//Since we don't want to save the nonce somewhere else in this case, we add it as a prefix to the encrypted data. The first nonce argument in Seal is the prefix.
	ciphertext := aesGCM.Seal(nonce, nonce, plaintext, nil)
	// set encrypted value
	enc.Body = fmt.Sprintf("%x", ciphertext)
	return nil
}
