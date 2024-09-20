package masktest

import (
	"errors"
	"strconv"
	"testing"

	"github.com/ln80/struct-sensitive/mask"
)

type Tc[T any] struct {
	Option func(*mask.Config[T])
	Value  string
	Want   string
	OK     bool
	Err    error
}

func Run[T any](t *testing.T, masker mask.Masker[T], tcs []Tc[T]) {
	t.Helper()
	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i+1), func(t *testing.T) {
			result, err := masker(tc.Value, tc.Option)
			if !tc.OK {
				if tc.Err == nil {
					if err == nil {
						t.Fatal("expect err not to be nil")
					}
					return
				}
				if !errors.Is(err, tc.Err) {
					t.Fatalf("expect err be %v, got %v", tc.Err, err)
				}
				return
			}
			if result != tc.Want {
				t.Fatalf("want %s, got %s", tc.Want, result)
			}
		})
	}
}
