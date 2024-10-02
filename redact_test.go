package sensitive

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
)

func TestRedact(t *testing.T) {
	type tc struct {
		val    any
		want   any
		option func(*RedactConfig)
		ok     bool
		err    error
	}

	tcs := []tc{
		{
			val: nil,
			ok:  false,
			err: ErrUnsupportedType,
		},
		{
			val: "070 a",
			ok:  false,
			err: ErrUnsupportedType,
		},
		{
			val: Address{Street: "07024 Quigley Trace"},
			ok:  false,
			err: ErrUnsupportedType,
		},
		{
			val:  &Address{Street: "07024 Quigley Trace"},
			want: &Address{Street: "*******************"},
			ok:   true,
		},
		{
			val:  &Address{Street: "070 a"},
			want: &Address{Street: "*****"},
			ok:   true,
		},
		func() tc {
			testErr := errors.New("test replace error")
			return tc{
				val: &Address{Street: "070 a"},
				option: func(rc *RedactConfig) {
					rc.RedactFunc = func(fr FieldReplace, val string) (string, error) {
						return "", testErr
					}
				},
				ok:  false,
				err: testErr,
			}
		}(),
		{
			val:  &Address{Street: "070 a"},
			want: &Address{Street: "*"},
			option: func(rc *RedactConfig) {
				rc.RedactFunc = func(fr FieldReplace, val string) (string, error) {
					return "*", nil
				}
			},
			ok: true,
		},
		{
			val:  &Address{Street: "070 a"},
			want: &Address{Street: "*"},
			option: func(rc *RedactConfig) {
				rc.RedactFunc = nil
			},
			ok:  false,
			err: ErrRedactFuncNotFound,
		},
		{
			val: &Profile{
				Email: "Vernon_Parker21@gmail.com",
				Phone: ptr("250-308-0529"),
			},
			want: &Profile{
				ID:    "",
				Email: "*************************",
				Phone: ptr("************"),
			},
			ok: true,
		},
		func() tc {
			type T struct {
				Profile `sensitive:"dive"`
				Address *Address `sensitive:"dive"`
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: &Address{Street: "07024 Quigley Trace"},
				},
				want: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "*****************",
					},
					Address: &Address{Street: "*******************"},
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Value string
			}
			return tc{
				val: &T{
					Value: "abc",
				},
				want: &T{
					Value: "abc",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Email    Email  `sensitive:"data"`
				Fullname string `sensitive:"data"`
			}
			return tc{
				val: &T{
					Email:    "email@example.com",
					Fullname: "Sarah Turcotte",
				},
				want: &T{
					Email:    "****@****.com",
					Fullname: "**************",
				},
				option: func(rc *RedactConfig) {
					rc.RedactFunc = func(fr FieldReplace, val string) (string, error) {
						switch {
						case fr.RType == reflect.TypeOf(Email("")):
							return "****@****.com", nil
						default:
							return RedactDefaultFunc(fr, val)
						}
					}
				},
				ok: true,
			}
		}(),
	}

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i+1), func(t *testing.T) {
			err := Redact(tc.val, tc.option)
			if !tc.ok {
				if tc.err == nil {
					if err == nil {
						t.Fatal("expect err not to be nil")
					}
					return
				}
				if !errors.Is(err, tc.err) {
					t.Fatalf("expect err is %v, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal("expect err be nil, got", err)
			}
			if !reflect.DeepEqual(tc.want, tc.val) {
				t.Fatalf("expect %s, %s be equals", tc.want, tc.val)
			}
		})
	}
}
