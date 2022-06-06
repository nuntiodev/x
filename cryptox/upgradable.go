package cryptox

import (
	"encoding/json"
	"reflect"
)

func (c *defaultCrypto) Upgradeble(enc interface{}) (bool, error) {
	v := reflect.Indirect(reflect.ValueOf(enc))
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
			if stringx.Body != "" && len(c.IKeys) > int(stringx.InternalEncryptionLevel) {
				return true, nil
			}
			// check external level
			if stringx.Body != "" && len(c.EKeys) > int(stringx.ExternalEncryptionLevel) {
				return true, nil
			}
		} else if reflect.Indirect(field).Kind() == reflect.Struct {
			//recursive encryption todo: find a faster way
			upgradable, _ := c.Upgradeble(field.Interface())
			if upgradable {
				return upgradable, nil
			}
			continue
		}
	}
	return false, nil
}
