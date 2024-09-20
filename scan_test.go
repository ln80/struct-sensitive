package sensitive

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
)

type Email string

type Profile struct {
	ID    string  `sensitive:"subjectID"`
	Email Email   `sensitive:"data"`
	Phone *string `sensitive:"data"`
}

type Address struct {
	Street string `sensitive:"data"`
}

func TestStruct_Scan(t *testing.T) {
	// replaceFn does empty sensitive fields. This particular behavior makes testing easier.
	replaceFn := func(fr FieldReplace, val string) (newVal string, err error) {
		return "", nil
	}

	type tc struct {
		val  any
		want any
		ok   bool
		err  error
	}
	tcs := []tc{
		{
			val: &Profile{
				ID:    "abc",
				Email: "email@example.com",
			},
			want: &Profile{
				ID: "abc",
			},
			ok: true,
		},
		{
			val: &Profile{
				ID:    "abc",
				Email: "email@example.com",
				Phone: ptr("519-491-6780"),
			},
			want: &Profile{
				ID:    "abc",
				Phone: ptr(""),
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
					Address: nil,
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: nil,
				},
				ok: true,
			}
		}(),
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
					Address: &Address{
						Street: "7234 Antone Springs",
					},
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: &Address{
						Street: "",
					},
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `sensitive:"dive"`
				Address []Address `sensitive:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: []Address{
						{
							Street: "7234 Antone Springs",
						},
						{
							Street: "90 Kerluke Pine DS",
						},
					},
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: []Address{
						{},
						{},
					},
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `sensitive:"dive"`
				Address []Address `sensitive:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `sensitive:"dive"`
				Address []*Address `sensitive:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: []*Address{
						{
							Street: "7234 Antone Springs",
						},
					},
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: []*Address{
						{},
					},
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `sensitive:"dive"`
				Address map[string]*Address `sensitive:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: map[string]*Address{
						"A": {
							Street: "7234 Antone Springs",
						},
					},
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: map[string]*Address{
						"A": {
							Street: "",
						},
					},
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `sensitive:"dive"`
				Address map[string]*Address `sensitive:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: nil,
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: nil,
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `sensitive:"dive"`
				Address map[string]Address `sensitive:"dive"`
				Company string
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: map[string]Address{
						"A": {
							Street: "7234 Antone Springs",
						},
					},
					Company: "company name",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: map[string]Address{
						"A": {
							Street: "",
						},
					},
					Company: "company name",
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `sensitive:"dive"`
				Child   *T `sensitive:"dive"`
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Child: &T{
						Profile: Profile{
							ID:    "abc",
							Email: "email.child@example.com",
						},
					},
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Child: &T{
						Profile: Profile{
							ID: "abc",
						},
					},
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				Profile `sensitive:"dive"`
				Child   *T `sensitive:"dive"`
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Child: &T{
						Profile: Profile{
							ID:    "abc_child",
							Email: "email.child@example.com",
						},
					},
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},

					Child: &T{
						Profile: Profile{
							ID: "abc_child",
						},
					},
				},
				ok:  false,
				err: ErrMultipleNestedSubjectID,
			}
		}(),
		func() tc {
			type NestedAddress struct {
				Address `sensitive:"dive"`
				Sub     *Address `sensitive:"dive"`
			}
			type T struct {
				Profile `sensitive:"dive"`
				Address NestedAddress `sensitive:"dive"`
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					Address: NestedAddress{
						Address: Address{
							Street: "7234 Antone Springs",
						},
						Sub: &Address{
							Street: "26559 Senger Crossing",
						},
					},
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					Address: NestedAddress{
						Address: Address{
							Street: "",
						},
						Sub: &Address{
							Street: "",
						},
					},
				},
				ok: true,
			}
		}(),
	}

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i+1), func(t *testing.T) {
			s, err := Scan(tc.val, true)
			if !tc.ok {
				if !errors.Is(err, tc.err) {
					t.Fatalf("expect err is %v, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal("expect err be nil, got", err)
			}
			_ = s.Replace(replaceFn)
			if !reflect.DeepEqual(tc.want, tc.val) {
				t.Fatalf("expect %s, %s be equals", tc.want, tc.val)
			}
		})
	}
}
