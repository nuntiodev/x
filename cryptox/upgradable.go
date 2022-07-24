package cryptox

import (
	"encoding/json"
	"errors"
	"reflect"
)

func (c *defaultCrypto) Upgradeble(enc interface{}) (bool, error) {
	if reflect.ValueOf(enc).Type().Kind() != reflect.Ptr {
		return false, errors.New("invalid value - needs to be a pointer to object")
	}
	v := reflect.Indirect(reflect.ValueOf(enc))
	if v.CanSet() == false {
		return false, errors.New("cannot update value in interface")
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
				return false, err
			}
			if err := json.Unmarshal(bytes, stringx); err != nil {
				return false, err
			}
			// check internal level
			if stringx.Body != "" && len(c.SymmetricKeys) > int(stringx.EncryptionLevel) {
				return true, nil
			}
		} else if reflect.Indirect(field).Kind() == reflect.Struct {
			//recursive encryption todo: find a faster way
			upgradable, _ := c.Upgradeble(field.Interface())
			if upgradable {
				return upgradable, nil
			}
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
						return false, err
					}
					stringx := &Stringx{}
					if err := json.Unmarshal(bytes, stringx); err != nil {
						return false, err
					}
					// check internal level
					if stringx.Body != "" && len(c.SymmetricKeys) > int(stringx.EncryptionLevel) {
						return true, nil
					}
				}
			}
		}
	}
	return false, nil
}
