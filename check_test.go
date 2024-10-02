package sensitive

import (
	"errors"
	"strconv"
	"testing"
)

func TestCheck(t *testing.T) {
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
			val: InvalidTag{Data: "abc"},
			ok:  false,
			err: ErrInvalidTagConfiguration,
		},
		{
			val: struct{ Val string }{Val: "value"},
			ok:  false,
		},
		{
			val: struct {
				Val struct{} `sensitive:"data"`
			}{Val: struct{}{}},
			ok: false,
		},
		{
			val: Address{Street: "578 Abbott Viaduct"},
			ok:  true,
		},
		{
			val: &Address{Street: "578 Abbott Viaduct"},
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
			ok, err := Check(tc.val)
			if got, want := err, tc.err; !errors.Is(got, want) {
				t.Fatalf("want %v got %v", got, want)
			}

			if got, want := ok, tc.ok; got != want {
				t.Fatalf("want %v got %v", want, got)
			}
		})
	}
}
