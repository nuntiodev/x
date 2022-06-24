package cryptox

import (
	"encoding/json"
	"reflect"
)

func (c *defaultCrypto) EncryptionLevel(val interface{}) (int32, int32) {
	v := reflect.Indirect(reflect.ValueOf(val))
	if v.CanSet() == false {
		return 0, 0
	}
	external := int32(0)
	internal := int32(0)
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
				continue
			}
			if err := json.Unmarshal(bytes, stringx); err != nil {
				continue
			}
			if stringx.EncryptionLevel > internal {
				internal = stringx.EncryptionLevel
			}
		} else if reflect.Indirect(field).Kind() == reflect.Struct {
			//recursive encryption todo: find a faster way
			internalLvl, externalLvl := c.EncryptionLevel(field.Interface())
			if internalLvl > internal {
				internal = internalLvl
			}
			if externalLvl > external {
				external = externalLvl
			}
		}
	}
	return internal, external
}
