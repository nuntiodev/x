package cryptox

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
)

func (c *defaultCrypto) Decrypt(dec interface{}) error {
	if reflect.ValueOf(dec).Type().Kind() != reflect.Ptr {
		return errors.New("invalid value - needs to be a pointer to object")
	}
	v := reflect.Indirect(reflect.ValueOf(dec))
	if v.CanSet() == false {
		return errors.New("cannot update value in interface")
	}
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
			// encrypt using  symmetric Keys
			if len(c.SymmetricKeys) > 0 && stringx.Body != "" && stringx.EncryptionLevel > 0 {
				// build new key of length stringx encryption level
				key, err := CombineSymmetricSymmetricKeys(c.SymmetricKeys, int(stringx.EncryptionLevel))
				if err != nil {
					return err
				}
				internalKey, err := hex.DecodeString(key)
				if err != nil {
					return err
				}
				if err := c.decrypt(stringx, internalKey); err != nil {
					return err
				}
			}
			if c.PrivateKey != nil && stringx.Body != "" && stringx.PublicKeyEncrypted == true {
				decryptedBytes, err := c.PrivateKey.Decrypt(nil, []byte(stringx.Body), &rsa.OAEPOptions{Hash: crypto.SHA256})
				if err != nil {
					return err
				}
				stringx.Body = string(decryptedBytes)
			}
			// update value in interface with new value
			if typePtrStringx {
				field.Set(reflect.ValueOf(stringx))
			} else {
				field.Set(reflect.ValueOf(*stringx))
			}
		} else if reflect.Indirect(field).Kind() == reflect.Struct {
			//recursive encryption todo: find a faster way
			c.Decrypt(field.Interface())
		}
	}
	return nil
}

func (c *defaultCrypto) decrypt(dec *Stringx, key []byte) error {
	if dec == nil {
		return errors.New("strinx is nil")
	}
	enc, err := hex.DecodeString(dec.Body)
	if err != nil {
		return err
	}
	//Create a new Cipher Block from the key
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	//Create a new GCM
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}
	//Get the nonce size
	nonceSize := aesGCM.NonceSize()
	//Extract the nonce from the encrypted data
	nonce, ciphertext := enc[:nonceSize], enc[nonceSize:]
	//Decrypt the data
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return err
	}
	dec.Body = fmt.Sprintf("%s", plaintext)
	return nil
}
