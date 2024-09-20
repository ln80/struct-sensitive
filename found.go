package sensitive

import (
	"fmt"
	"reflect"
)

// Found returns wether or not the struct contains sensitive data fields.
// It returns an error if tag is misconfigured or the value param isn't a struct or struct pointer.
func Found(v any) (bool, error) {
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false, fmt.Errorf("%w : %v", ErrUnsupportedType, t)
	}

	ssT, err := scanStructType(t)
	if err != nil {
		return false, err
	}

	return ssT.hasSensitive, nil
}
