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
			bytes, err := json.Marshal(field.Interface())
			if err != nil {
				return err
			}
			stringx, err := c.createDecryptionStringx(bytes)
			if err != nil {
				return err
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
		} else if reflect.Indirect(field).Kind() == reflect.Map { // handle map type
			mapTypePtrStringx := reflect.Indirect(field).Type().Elem() == reflect.TypeOf(&Stringx{})
			mapTypeStringx := reflect.Indirect(field).Type().Elem() == reflect.TypeOf(Stringx{})
			if mapTypePtrStringx || mapTypeStringx {
				vMap := reflect.ValueOf(field.Interface())
				iterator := vMap.MapRange()
				for iterator.Next() {
					mapValue := iterator.Value()
					bytes, err := json.Marshal(mapValue.Interface())
					if err != nil {
						return err
					}
					stringx, err := c.createDecryptionStringx(bytes)
					if err != nil {
						return err
					}
					if mapTypePtrStringx {
						vMap.SetMapIndex(reflect.ValueOf(iterator.Key().Interface()), reflect.ValueOf(stringx))
					} else {
						vMap.SetMapIndex(reflect.ValueOf(iterator.Key().Interface()), reflect.ValueOf(*stringx))
					}
				}
			}
		}
	}
	return nil
}

func (c *defaultCrypto) createDecryptionStringx(bytes []byte) (*Stringx, error) {
	stringx := &Stringx{}
	if err := json.Unmarshal(bytes, stringx); err != nil {
		return nil, err
	}
	// encrypt using  symmetric Keys
	if len(c.SymmetricKeys) > 0 && stringx.Body != "" && stringx.EncryptionLevel > 0 {
		// build new key of length stringx encryption level
		key, err := CombineSymmetricSymmetricKeys(c.SymmetricKeys, int(stringx.EncryptionLevel))
		if err != nil {
			return nil, err
		}
		internalKey, err := hex.DecodeString(key)
		if err != nil {
			return nil, err
		}
		if err := c.decrypt(stringx, internalKey); err != nil {
			return nil, err
		}
	}
	if c.PrivateKey != nil && stringx.Body != "" && stringx.PublicKeyEncrypted == true {
		decryptedBytes, err := c.PrivateKey.Decrypt(nil, []byte(stringx.Body), &rsa.OAEPOptions{Hash: crypto.SHA256})
		if err != nil {
			return nil, err
		}
		stringx.Body = string(decryptedBytes)
	}
	return stringx, nil
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
