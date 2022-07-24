package cryptox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
)

func (c *defaultCrypto) Encrypt(enc interface{}) error {
	if reflect.ValueOf(enc).Type().Kind() != reflect.Ptr {
		return errors.New("invalid value - needs to be a pointer to object")
	}
	v := reflect.Indirect(reflect.ValueOf(enc))
	if v.CanSet() == false {
		return errors.New("cannot update value in interface")
	}
	// todo: make this async
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
			stringx, err := c.createEncryptionStringx(bytes)
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
			c.Encrypt(field.Interface()) // do not catch
			continue
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
					stringx, err := c.createEncryptionStringx(bytes)
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
		} else if reflect.Indirect(field).Kind() == reflect.Array {
			// todo: implemet
		}
	}
	return nil
}

func (c *defaultCrypto) createEncryptionStringx(bytes []byte) (*Stringx, error) {
	// we accept types of Stringx or ptr Stringx
	stringx := &Stringx{}
	if err := json.Unmarshal(bytes, stringx); err != nil {
		return nil, err
	}
	// encrypt using public key first
	if c.PublicKey != nil {
		encryptedBytes, err := rsa.EncryptOAEP(
			sha256.New(),
			rand.Reader,
			c.PublicKey,
			[]byte(stringx.Body),
			nil)
		if err != nil {
			return nil, err
		}
		stringx.Body = string(encryptedBytes)
		stringx.PublicKeyEncrypted = true
	} else {
		stringx.PublicKeyEncrypted = false
	}
	// encrypt using symmetric keys
	if len(c.SymmetricKeys) > 0 && stringx.Body != "" {
		if err := c.encrypt(stringx, c.SymmetricKey); err != nil {
			return nil, err
		}
		stringx.EncryptionLevel = int32(len(c.SymmetricKeys))
	}
	return stringx, nil
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
