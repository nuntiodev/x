package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
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
			// order matters - need to be reverse of encryption order
			// encrypt using external keys
			if len(c.eKeys) > 0 && stringx.Body != "" {
				// build new key of length stringx.internalEncryptionLevel
				key, err := CombineSymmetricKeys(c.eKeys, int(stringx.ExternalEncryptionLevel))
				if err != nil {
					return err
				}
				externalKey, err := hex.DecodeString(key)
				if err != nil {
					return err
				}
				if err := c.decrypt(stringx, externalKey); err != nil {
					return err
				}
			}
			// encrypt using internal keys
			if len(c.iKeys) > 0 && stringx.Body != "" {
				// build new key of length stringx.internalEncryptionLevel
				key, err := CombineSymmetricKeys(c.iKeys, int(stringx.InternalEncryptionLevel))
				if err != nil {
					return err
				}
				internlKey, err := hex.DecodeString(key)
				if err != nil {
					return err
				}
				if err := c.decrypt(stringx, internlKey); err != nil {
					return err
				}
			}
			// update value in interface with new value
			if typePtrStringx {
				field.Set(reflect.ValueOf(stringx))
			} else {
				field.Set(reflect.ValueOf(*stringx))
			}
		} else if reflect.Indirect(field).Kind() == reflect.Struct {
			//recursive encryption todo: find a faster way
			err := c.Decrypt(field.Interface())
			if err != nil {
				return err
			}
			continue
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
