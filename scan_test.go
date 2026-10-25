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
				ok:  false,
				err: ErrUnsupportedFieldType,
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
				ok: true,
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

func TestSubjectIDResolution(t *testing.T) {
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
	type withPtr struct {
		ID    *string `sensitive:"subjectID"`
		Email string  `sensitive:"data"`
	}
	type withPtrPtr struct {
		ID **string `sensitive:"subjectID"`
	}
	id := "u1"

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
		{name: "pointer string", val: &withPtr{ID: &id, Email: "a@b.c"}, want: "u1"},
		{name: "pointer to pointer", val: &withPtrPtr{ID: ptr(&id)}, wantErr: ErrUnsupportedFieldType},
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

func TestTaggedFieldsMustBeHandled(t *testing.T) {
	type contact struct {
		Email string `sensitive:"data"`
	}
	type withEmbed struct {
		ID string `sensitive:"subjectID"`
		contact
	}
	type withBytes struct {
		ID    string   `sensitive:"subjectID"`
		Parts [][]byte `sensitive:"data"`
	}
	type withInt struct {
		ID string `sensitive:"subjectID"`
		N  int    `sensitive:"data"`
	}
	type withArray struct {
		ID   string    `sensitive:"subjectID"`
		Tags [1]string `sensitive:"data"`
	}
	type withMap struct {
		ID   string            `sensitive:"subjectID"`
		Tags map[string]string `sensitive:"data"`
	}
	type withAny struct {
		ID string `sensitive:"subjectID"`
		V  any    `sensitive:"data"`
	}
	type withDoublePtr struct {
		ID string   `sensitive:"subjectID"`
		V  **string `sensitive:"data"`
	}
	type withStruct struct {
		ID string  `sensitive:"subjectID"`
		V  contact `sensitive:"data"`
	}

	t.Run("embedded", func(t *testing.T) {
		in := &withEmbed{ID: "u1", contact: contact{Email: "a@b.c"}}
		s, err := Scan(in, true)
		if err != nil {
			t.Fatalf("Scan() err = %v", err)
		}
		if err := s.Replace(func(FieldReplace, string) (string, error) { return "", nil }); err != nil {
			t.Fatalf("Replace() err = %v", err)
		}
		if in.Email != "" {
			t.Fatalf("Email = %q, want empty", in.Email)
		}
	})

	t.Run("byte slices", func(t *testing.T) {
		in := &withBytes{ID: "u1", Parts: [][]byte{[]byte("a"), []byte("b")}}
		s, err := Scan(in, true)
		if err != nil {
			t.Fatalf("Scan() err = %v", err)
		}
		if err := s.Replace(func(FieldReplace, string) (string, error) { return "", nil }); err != nil {
			t.Fatalf("Replace() err = %v", err)
		}
		for i, part := range in.Parts {
			if string(part) != "" {
				t.Fatalf("Parts[%d] = %q, want empty", i, part)
			}
		}
	})

	errCases := []struct {
		name string
		val  any
	}{
		{name: "int", val: &withInt{ID: "u1", N: 42}},
		{name: "array", val: &withArray{ID: "u1", Tags: [1]string{"a"}}},
		{name: "map", val: &withMap{ID: "u1", Tags: map[string]string{"a": "b"}}},
		{name: "any", val: &withAny{ID: "u1", V: "x"}},
		{name: "double pointer", val: &withDoublePtr{ID: "u1"}},
		{name: "struct", val: &withStruct{ID: "u1", V: contact{Email: "a@b.c"}}},
	}
	for _, tc := range errCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Scan(tc.val, true)
			if !errors.Is(err, ErrUnsupportedFieldType) {
				t.Fatalf("Scan() err = %v, want %v", err, ErrUnsupportedFieldType)
			}
		})
	}
}

func TestPerElementSubject(t *testing.T) {
	type member struct {
		ID    string `sensitive:"subjectID"`
		Email string `sensitive:"data"`
	}
	type group struct {
		Members []member `sensitive:"dive"`
	}
	type groupMap struct {
		Members map[string]member `sensitive:"dive"`
	}
	type kid struct {
		Email string `sensitive:"data"`
	}
	type parent struct {
		ID  string `sensitive:"subjectID"`
		Kid kid    `sensitive:"dive"`
	}
	type viewer struct {
		ID    string `sensitive:"subjectID"`
		Email string `sensitive:"data"`
	}
	type event struct {
		Note   string `sensitive:"data"`
		Viewer viewer `sensitive:"dive"`
	}

	t.Run("slice", func(t *testing.T) {
		in := &group{Members: []member{{ID: "u1", Email: "a@b.c"}, {ID: "u2", Email: "c@d.e"}}}
		s, err := Scan(in, true)
		if err != nil {
			t.Fatalf("Scan() err = %v", err)
		}
		if got := s.SubjectID(); got != "" {
			t.Fatalf("SubjectID() = %q, want empty", got)
		}
		got := map[string]string{}
		if err := s.Replace(func(fr FieldReplace, val string) (string, error) {
			got[val] = fr.SubjectID
			return val, nil
		}); err != nil {
			t.Fatalf("Replace() err = %v", err)
		}
		if got["a@b.c"] != "u1" || got["c@d.e"] != "u2" {
			t.Fatalf("subjects = %v", got)
		}
	})

	t.Run("map", func(t *testing.T) {
		in := &groupMap{Members: map[string]member{
			"a": {ID: "u1", Email: "a@b.c"},
			"b": {ID: "u2", Email: "c@d.e"},
		}}
		subjects := func() map[string]string {
			s, err := Scan(in, true)
			if err != nil {
				t.Fatalf("Scan() err = %v", err)
			}
			got := map[string]string{}
			if err := s.Replace(func(fr FieldReplace, val string) (string, error) {
				got[val] = fr.SubjectID
				return val, nil
			}); err != nil {
				t.Fatalf("Replace() err = %v", err)
			}
			return got
		}
		first := subjects()
		second := subjects()
		if first["a@b.c"] != "u1" || first["c@d.e"] != "u2" || !reflect.DeepEqual(first, second) {
			t.Fatalf("subjects = %v and %v", first, second)
		}
	})

	t.Run("inherit parent", func(t *testing.T) {
		in := &parent{ID: "u1", Kid: kid{Email: "a@b.c"}}
		s, err := Scan(in, true)
		if err != nil {
			t.Fatalf("Scan() err = %v", err)
		}
		var got string
		if err := s.Replace(func(fr FieldReplace, _ string) (string, error) {
			got = fr.SubjectID
			return "", nil
		}); err != nil {
			t.Fatalf("Replace() err = %v", err)
		}
		if got != "u1" {
			t.Fatalf("SubjectID = %q, want u1", got)
		}
	})

	t.Run("root data uses nested subject", func(t *testing.T) {
		in := &event{Note: "hello", Viewer: viewer{ID: "u1", Email: "a@b.c"}}
		s, err := Scan(in, true)
		if err != nil {
			t.Fatalf("Scan() err = %v", err)
		}
		if got := s.SubjectID(); got != "u1" {
			t.Fatalf("SubjectID() = %q, want u1", got)
		}
		got := map[string]string{}
		if err := s.Replace(func(fr FieldReplace, val string) (string, error) {
			got[val] = fr.SubjectID
			return val, nil
		}); err != nil {
			t.Fatalf("Replace() err = %v", err)
		}
		if got["hello"] != "u1" || got["a@b.c"] != "u1" {
			t.Fatalf("subjects = %v", got)
		}
	})
}

func TestNilAndUnsupportedDoNotPanic(t *testing.T) {
	type member struct {
		ID    string `sensitive:"subjectID"`
		Email string `sensitive:"data"`
	}
	type ptrGroup struct {
		Members []*member `sensitive:"dive"`
	}
	type names struct {
		ID    string    `sensitive:"subjectID"`
		Names []*string `sensitive:"data"`
	}
	type badDive struct {
		ID      string `sensitive:"subjectID"`
		Payload any    `sensitive:"dive"`
	}

	t.Run("nil pointer element", func(t *testing.T) {
		m := &member{ID: "u1", Email: "a@b.c"}
		in := &ptrGroup{Members: []*member{m, nil}}
		s, err := Scan(in, true)
		if err != nil {
			t.Fatalf("Scan() err = %v", err)
		}
		if err := s.Replace(func(FieldReplace, string) (string, error) { return "", nil }); err != nil {
			t.Fatalf("Replace() err = %v", err)
		}
		if m.Email != "" {
			t.Fatalf("Email = %q, want empty", m.Email)
		}
	})

	t.Run("nil string element", func(t *testing.T) {
		name := "ann"
		in := &names{ID: "u1", Names: []*string{&name, nil}}
		s, err := Scan(in, true)
		if err != nil {
			t.Fatalf("Scan() err = %v", err)
		}
		if err := s.Replace(func(FieldReplace, string) (string, error) { return "", nil }); err != nil {
			t.Fatalf("Replace() err = %v", err)
		}
		if name != "" {
			t.Fatalf("name = %q, want empty", name)
		}
	})

	t.Run("dive any", func(t *testing.T) {
		_, err := Scan(&badDive{ID: "u1", Payload: "x"}, true)
		if !errors.Is(err, ErrUnsupportedFieldType) {
			t.Fatalf("Scan() err = %v, want %v", err, ErrUnsupportedFieldType)
		}
	})

	t.Run("nil check", func(t *testing.T) {
		_, err := Check(nil)
		if !errors.Is(err, ErrUnsupportedType) {
			t.Fatalf("Check() err = %v, want %v", err, ErrUnsupportedType)
		}
	})

	t.Run("nil field tag", func(t *testing.T) {
		_, err := FieldTag(nil, "ID")
		if !errors.Is(err, ErrUnsupportedType) {
			t.Fatalf("FieldTag() err = %v, want %v", err, ErrUnsupportedType)
		}
	})

	t.Run("dive string", func(t *testing.T) {
		_, err := Scan(&struct {
			ID   string `sensitive:"subjectID"`
			Name string `sensitive:"dive"`
		}{ID: "u1", Name: "ann"}, true)
		if !errors.Is(err, ErrUnsupportedFieldType) {
			t.Fatalf("Scan() err = %v, want %v", err, ErrUnsupportedFieldType)
		}
	})

	t.Run("dive array", func(t *testing.T) {
		_, err := Scan(&struct {
			ID      string    `sensitive:"subjectID"`
			Members [2]member `sensitive:"dive"`
		}{}, true)
		if !errors.Is(err, ErrUnsupportedFieldType) {
			t.Fatalf("Scan() err = %v, want %v", err, ErrUnsupportedFieldType)
		}
	})

	t.Run("dive map of slice", func(t *testing.T) {
		_, err := Scan(&struct {
			ID      string              `sensitive:"subjectID"`
			Members map[string][]member `sensitive:"dive"`
		}{}, true)
		if !errors.Is(err, ErrUnsupportedFieldType) {
			t.Fatalf("Scan() err = %v, want %v", err, ErrUnsupportedFieldType)
		}
	})
}

func TestFailedScanDoesNotPoisonCache(t *testing.T) {
	type poisonInner struct {
		Email string `sensitive:"dat"`
	}
	type poisonOuter struct {
		Inner poisonInner `sensitive:"dive"`
	}

	if _, err := Scan(&poisonOuter{}, false); err == nil {
		t.Fatal("Scan(outer) err = nil, want tag error")
	}
	if _, err := Scan(&poisonInner{Email: "a@b.c"}, false); err == nil {
		t.Fatal("Scan(inner) err = nil, want tag error")
	}
	found, err := Check(poisonInner{Email: "a@b.c"})
	if err == nil || found {
		t.Fatalf("Check() = %v, %v; want an error", found, err)
	}
}

func TestFieldReplacePath(t *testing.T) {
	type dev struct {
		IP string `sensitive:"data"`
	}
	type profile struct {
		Email   string         `sensitive:"data"`
		Devices []dev          `sensitive:"dive"`
		Labels  map[string]dev `sensitive:"dive"`
		Tags    []string       `sensitive:"data"`
	}
	in := &profile{
		Email:   "a@b.c",
		Devices: []dev{{IP: "10.0.0.1"}},
		Labels: map[string]dev{
			"b": {IP: "10.0.0.2"},
			"a": {IP: "10.0.0.3"},
		},
		Tags: []string{"one", "two"},
	}
	paths := func() map[string]string {
		t.Helper()
		s, err := Scan(in, false)
		if err != nil {
			t.Fatalf("Scan() err = %v", err)
		}
		got := map[string]string{}
		if err := s.Replace(func(fr FieldReplace, val string) (string, error) {
			got[val] = fr.Path
			if fr.Name == "" {
				t.Fatal("Name is empty")
			}
			return val, nil
		}); err != nil {
			t.Fatalf("Replace() err = %v", err)
		}
		return got
	}
	first := paths()
	second := paths()
	want := map[string]string{
		"a@b.c":    "Email",
		"10.0.0.1": "Devices[0].IP",
		"10.0.0.3": "Labels[0].IP",
		"10.0.0.2": "Labels[1].IP",
		"one":      "Tags[0]",
		"two":      "Tags[1]",
	}
	if !reflect.DeepEqual(first, want) || !reflect.DeepEqual(second, want) {
		t.Fatalf("paths = %v and %v, want %v", first, second, want)
	}
}

func TestFieldReplaceOptionsAreIsolated(t *testing.T) {
	type row struct {
		Email string `sensitive:"data,kind=email"`
	}
	replace := func(in *row) string {
		t.Helper()
		s, err := Scan(in, false)
		if err != nil {
			t.Fatalf("Scan() err = %v", err)
		}
		var kind string
		if err := s.Replace(func(fr FieldReplace, val string) (string, error) {
			kind = fr.Options["kind"]
			fr.Options["kind"] = "mutated"
			return val, nil
		}); err != nil {
			t.Fatalf("Replace() err = %v", err)
		}
		return kind
	}
	if got := replace(&row{Email: "a@b.c"}); got != "email" {
		t.Fatalf("first kind = %q", got)
	}
	if got := replace(&row{Email: "c@d.e"}); got != "email" {
		t.Fatalf("second kind = %q", got)
	}
}

func TestReplaceLeavesValueUnchangedOnError(t *testing.T) {
	type row struct {
		ID     string `sensitive:"subjectID"`
		Email  string `sensitive:"data"`
		Name   string `sensitive:"data"`
		Secret []byte `sensitive:"data"`
	}
	in := &row{ID: "u1", Email: "a@b.c", Name: "Ann", Secret: []byte("secret")}
	s, err := Scan(in, true)
	if err != nil {
		t.Fatalf("Scan() err = %v", err)
	}
	n := 0
	err = s.Replace(func(FieldReplace, string) (string, error) {
		n++
		if n == 2 {
			return "", errors.New("stop")
		}
		return "ENC", nil
	})
	if err == nil {
		t.Fatal("Replace() err = nil, want callback error")
	}
	if in.Email != "a@b.c" || in.Name != "Ann" || string(in.Secret) != "secret" {
		t.Fatalf("value changed: %+v", in)
	}

	fresh := &row{ID: "u1", Email: "a@b.c", Name: "Ann", Secret: []byte("secret")}
	s, err = Scan(fresh, true)
	if err != nil {
		t.Fatalf("Scan() err = %v", err)
	}
	plan, err := s.Plan(func(FieldReplace, string) (string, error) {
		return "", nil
	})
	if err != nil {
		t.Fatalf("Plan() err = %v", err)
	}
	if fresh.Email != "a@b.c" || string(fresh.Secret) != "secret" {
		t.Fatal("Plan wrote the value")
	}
	if err := plan.Commit(); err != nil {
		t.Fatalf("Commit() err = %v", err)
	}
	if fresh.Email != "" || fresh.Name != "" || string(fresh.Secret) != "" {
		t.Fatalf("Commit() value = %+v", fresh)
	}
}

func TestValueCycle(t *testing.T) {
	type node struct {
		ID     string `sensitive:"subjectID"`
		Secret string `sensitive:"data"`
		Next   *node  `sensitive:"dive"`
	}
	loop := &node{ID: "u1", Secret: "x"}
	loop.Next = loop
	if _, err := Scan(loop, false); !errors.Is(err, ErrCycle) {
		t.Fatalf("Scan() err = %v, want %v", err, ErrCycle)
	}
	if errors.Is(errCycle(loop), ErrInvalidTagConfiguration) {
		t.Fatal("cycle was reported as a bad tag")
	}

	a := &node{ID: "u1", Secret: "x"}
	b := &node{ID: "u2", Secret: "y"}
	a.Next = b
	s, err := Scan(a, false)
	if err != nil {
		t.Fatalf("Scan() err = %v", err)
	}
	b.Next = a
	if err := s.Replace(func(FieldReplace, string) (string, error) {
		return "z", nil
	}); !errors.Is(err, ErrCycle) {
		t.Fatalf("Replace() err = %v, want %v", err, ErrCycle)
	}
	if a.Secret != "x" || b.Secret != "y" {
		t.Fatalf("cycle replace wrote values: %+v %+v", a, b)
	}
}

func errCycle(v any) error {
	_, err := Scan(v, false)
	return err
}

func TestWalkDepthIsBounded(t *testing.T) {
	type node struct {
		Secret string `sensitive:"data"`
		Next   *node  `sensitive:"dive"`
	}
	head := &node{Secret: "x"}
	cur := head
	for i := 0; i < maxWalkDepth; i++ {
		cur.Next = &node{Secret: "x"}
		cur = cur.Next
	}
	if _, err := Scan(head, false); !errors.Is(err, ErrMaxDepth) {
		t.Fatalf("Scan() err = %v, want %v", err, ErrMaxDepth)
	}
}

func TestMissingSubjectIsNotTagConfiguration(t *testing.T) {
	type row struct {
		Email string `sensitive:"data"`
	}
	_, err := Scan(&row{Email: "a@b.c"}, true)
	if !errors.Is(err, ErrSubjectIDNotFound) {
		t.Fatalf("Scan() err = %v, want %v", err, ErrSubjectIDNotFound)
	}
	if errors.Is(err, ErrInvalidTagConfiguration) {
		t.Fatalf("missing subject reported as a bad tag: %v", err)
	}
}

func TestSubjectIDDoesNotReresolve(t *testing.T) {
	type row struct {
		ID    string `sensitive:"subjectID"`
		Email string `sensitive:"data"`
	}
	in := &row{ID: "u1", Email: "a@b.c"}
	s, err := Scan(in, false)
	if err != nil {
		t.Fatalf("Scan() err = %v", err)
	}
	in.ID = "u2"
	if got := s.SubjectID(); got != "u1" {
		t.Fatalf("SubjectID() = %q after mutation", got)
	}

	type node struct {
		Secret string `sensitive:"data"`
		Next   *node  `sensitive:"dive"`
	}
	n := &node{Secret: "x"}
	s, err = Scan(n, false)
	if err != nil {
		t.Fatalf("Scan() err = %v", err)
	}
	n.Next = n
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("SubjectID() did not panic")
		}
	}()
	_ = s.SubjectID()
}
