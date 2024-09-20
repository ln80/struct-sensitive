package sensitive

import (
	"errors"
	"fmt"
	"reflect"
)

// Found returns wether or not the struct contains sensitive data fields.
// It returns an error if 'sensitive' tag is misconfigured or the value param isn't a struct or struct pointer.
func Found(v any) (found bool, err error) {
	defer func() {
		// normalize error
		if err != nil && !errors.Is(err, ErrUnsupportedType) {
			err = errors.Join(ErrInvalidTagConfiguration, err)
		}
	}()
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		err = fmt.Errorf("%w '%v'", ErrUnsupportedType, t)
		return
	}

	ssT, err := scanStructType(t)
	if err != nil {
		return

	}

	found = ssT.hasSensitive
	return
}
