package sensitive

import (
	"errors"
	"strconv"
	"testing"
)

func TestStruct_Found(t *testing.T) {
	type tc struct {
		val any
		ok  bool
		err error
	}

	tcs := []tc{
		{
			val: Email("email@example.com"),
			ok:  false,
			err: ErrUnsupportedType,
		},
		{
			val: struct{ Val string }{Val: "value"},
			ok:  false,
		},
		{
			val: Address{Street: "578 Abbott Viaduct"},
			ok:  true,
		},
		{
			val: struct {
				Address Address `sensitive:"dive"`
			}{Address: Address{Street: "578 Abbott Viaduct"}},
			ok: true,
		},
	}

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i+1), func(t *testing.T) {

			ok, err := Found(tc.val)

			if got, want := err, tc.err; !errors.Is(got, want) {
				t.Fatalf("expect %v, %v be equals", got, want)
			}

			if got, want := ok, tc.ok; got != want {
				t.Fatalf("expect %v, %v be equals", got, want)
			}
		})
	}
}
