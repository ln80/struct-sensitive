package sensitive

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
)

func TestScan(t *testing.T) {
	type tc struct {
		val  any
		want any
		ok   bool
		err  error
	}
	tcs := []tc{
		{
			val: ptr(&Profile{
				ID:    "abc",
				Email: "email@example.com",
			}),
			ok:  false,
			err: ErrUnsupportedType,
		},
		{
			val: &InvalidSubject{
				Subject:  "abc",
				Subject2: "abc2",
			},
			ok:  false,
			err: ErrInvalidTagConfiguration,
		},
		{
			val: &InvalidTag{
				Data: "abc",
			},
			ok:  false,
			err: ErrInvalidTagConfiguration,
		},
		{
			val: &InvalidSubject{
				Subject:  "abc",
				Subject2: "abc2",
			},
			ok:  false,
			err: ErrInvalidTagConfiguration,
		},
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
				ID     string `sensitive:"subjectID"`
				Secret []byte `sensitive:"data"`
			}
			return tc{
				val: &T{
					ID:     "abc",
					Secret: []byte("company name"),
				},
				want: &T{
					ID:     "abc",
					Secret: []byte(""),
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
				ignore  string `sensitive:"data"`
			}
			return tc{
				val: &T{
					Profile: Profile{
						ID:    "abc",
						Email: "email@example.com",
					},
					ignore: "abc",
				},
				want: &T{
					Profile: Profile{
						ID: "abc",
					},
					ignore: "abc",
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
		func() tc {
			type T struct {
				ID   string   `sensitive:"subjectID"`
				Tags []string `sensitive:"data"`
			}
			return tc{
				val: &T{
					ID:   "abc",
					Tags: []string{"tag1", "tag2", "tag3"},
				},
				want: &T{
					ID:   "abc",
					Tags: []string{"", "", ""},
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				ID   string   `sensitive:"subjectID"`
				Tags []string `sensitive:"data"`
			}
			return tc{
				val: &T{
					ID:   "abc",
					Tags: nil,
				},
				want: &T{
					ID:   "abc",
					Tags: nil,
				},
				ok: true,
			}
		}(),
		func() tc {
			type T struct {
				ID    string    `sensitive:"subjectID"`
				Names []*string `sensitive:"data"`
			}
			return tc{
				val: &T{
					ID:    "abc",
					Names: []*string{ptr("Alice"), ptr("Bob")},
				},
				want: &T{
					ID:    "abc",
					Names: []*string{ptr(""), ptr("")},
				},
				ok: true,
			}
		}(),
	}

	// replaceFn does empty sensitive fields. This particular behavior makes testing easier.
	replaceFn := func(fr FieldReplace, val string) (newVal string, err error) {
		return "", nil
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
			if !reflect.DeepEqual("abc", s.SubjectID()) {
				t.Fatalf("expect %s, %s be equals", tc.want, tc.val)
			}
		})
	}
}

func TestSS01_SubjectIDResolution(t *testing.T) {
	type userID string
	type rawID []byte
	type userInt int

	type withString struct {
		ID    string `sensitive:"subjectID"`
		Email string `sensitive:"data"`
	}
	type withNamedString struct {
		ID    userID `sensitive:"subjectID"`
		Email string `sensitive:"data"`
	}
	type withBytes struct {
		ID    []byte `sensitive:"subjectID"`
		Email string `sensitive:"data"`
	}
	type withNamedBytes struct {
		ID    rawID  `sensitive:"subjectID"`
		Email string `sensitive:"data"`
	}
	type withPrefix struct {
		ID    string `sensitive:"subjectID,prefix=usr_"`
		Email string `sensitive:"data"`
	}
	type withBytesPrefix struct {
		ID    []byte `sensitive:"subjectID,prefix=usr_"`
		Email string `sensitive:"data"`
	}
	type withInt struct {
		ID int `sensitive:"subjectID"`
	}
	type withInt64 struct {
		ID int64 `sensitive:"subjectID"`
	}
	type withUint struct {
		ID uint `sensitive:"subjectID"`
	}
	type withNamedInt struct {
		ID userInt `sensitive:"subjectID"`
	}
	type withRunes struct {
		ID []rune `sensitive:"subjectID"`
	}

	tcs := []struct {
		name    string
		val     any
		want    string
		wantErr error
	}{
		{name: "string u1", val: &withString{ID: "u1", Email: "a@b.c"}, want: "u1"},
		{name: "string u2", val: &withString{ID: "u2", Email: "a@b.c"}, want: "u2"},
		{name: "named string", val: &withNamedString{ID: "u1", Email: "a@b.c"}, want: "u1"},
		{name: "bytes u1", val: &withBytes{ID: []byte("u1"), Email: "a@b.c"}, want: "u1"},
		{name: "bytes u2", val: &withBytes{ID: []byte("u2"), Email: "a@b.c"}, want: "u2"},
		{name: "named bytes", val: &withNamedBytes{ID: rawID("u1"), Email: "a@b.c"}, want: "u1"},
		{name: "prefix string", val: &withPrefix{ID: "1", Email: "a@b.c"}, want: "usr_1"},
		{name: "prefix bytes", val: &withBytesPrefix{ID: []byte("1"), Email: "a@b.c"}, want: "usr_1"},
		{name: "int", val: &withInt{ID: 1}, wantErr: ErrUnsupportedFieldType},
		{name: "int64", val: &withInt64{ID: 2}, wantErr: ErrUnsupportedFieldType},
		{name: "uint", val: &withUint{ID: 3}, wantErr: ErrUnsupportedFieldType},
		{name: "named int", val: &withNamedInt{ID: 4}, wantErr: ErrUnsupportedFieldType},
		{name: "runes", val: &withRunes{ID: []rune("u1")}, wantErr: ErrUnsupportedFieldType},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			s, err := Scan(tc.val, true)
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("Scan() err = %v, want %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("Scan() err = %v", err)
			}
			if got := s.SubjectID(); got != tc.want {
				t.Fatalf("SubjectID() = %q, want %q", got, tc.want)
			}

			var got string
			if err := s.Replace(func(fr FieldReplace, _ string) (string, error) {
				got = fr.SubjectID
				return "", nil
			}); err != nil {
				t.Fatalf("Replace() err = %v", err)
			}
			if got != tc.want {
				t.Fatalf("FieldReplace.SubjectID = %q, want %q", got, tc.want)
			}
		})
	}
}
