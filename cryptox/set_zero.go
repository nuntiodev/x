package cryptox

import (
	"encoding/json"
	"errors"
	"reflect"
)

func (c *defaultCrypto) SetZero(enc interface{}) error {
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
			// we accept types of Stringx or ptr Stringx
			stringx := &Stringx{}
			bytes, err := json.Marshal(field.Interface())
			if err != nil {
				return err
			}
			if err := json.Unmarshal(bytes, stringx); err != nil {
				return err
			}
			stringx.ExternalEncryptionLevel = 0
			stringx.InternalEncryptionLevel = 0
			// update value in interface with new value
			if typePtrStringx {
				field.Set(reflect.ValueOf(stringx))
			} else {
				field.Set(reflect.ValueOf(*stringx))
			}
		} else if reflect.Indirect(field).Kind() == reflect.Struct {
			//recursive encryption todo: find a faster way
			c.SetZero(field.Interface()) // do not catch
			continue
		}
	}
	return nil
}
