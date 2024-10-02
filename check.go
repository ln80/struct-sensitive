package sensitive

import (
	"errors"
	"fmt"
	"reflect"
)

// Check verifies whether the provided struct contains sensitive data fields.
// It returns an error if the 'sensitive' tag is misconfigured or if the value parameter
// is not a struct or a pointer to a struct.
func Check(v any) (found bool, err error) {
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
