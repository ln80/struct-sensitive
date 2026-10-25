package sensitive

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
)

func TestTag_Parse(t *testing.T) {
	type tc struct {
		val  any
		want *TagPayload
		ok   bool
	}

	tcs := []tc{
		{
			val: struct {
				_ bool
			}{},
			want: nil,
			ok:   false,
		},
		{
			val: struct {
				_ bool `invalid:"data"`
			}{},
			want: nil,
			ok:   false,
		},
		{
			val: struct {
				_ bool `sensitive:"data"`
			}{},
			want: &TagPayload{
				ID:      "sensitive",
				Name:    "data",
				Options: make(TagOptions),
			},
			ok: true,
		},
		{
			val: struct {
				_ bool `sensitive:"subjectID,prefix=accounting"`
			}{},
			want: &TagPayload{
				ID:      "sensitive",
				Name:    "subjectID",
				Options: map[string]string{"prefix": "accounting"},
			},
			ok: true,
		},
		{
			val: struct {
				_ bool `pii:"dive"`
			}{},
			want: &TagPayload{
				ID:      "pii",
				Name:    "dive",
				Options: map[string]string{},
			},
			ok: true,
		},
	}
	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i), func(t *testing.T) {
			rawTag := reflect.TypeOf(tc.val).Field(0).Tag
			payload, err := ParseTag(rawTag)
			if !tc.ok {
				if err != nil {
					t.Fatal(err)
				}
				if payload != nil {
					t.Fatal("expect payload be nil got", payload)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if want, got := tc.want, payload; !reflect.DeepEqual(want, got) {
				t.Fatalf("want %+v, got %+v", want, got)
			}
			if want, got := string(rawTag), payload.Marshal(); want != got {
				t.Fatalf("want '%v', got '%v'", want, got)
			}
		})
	}
}

func TestParseTagRejectsBadOptions(t *testing.T) {
	cases := []struct {
		name string
		val  any
	}{
		{
			name: "unknown option",
			val: struct {
				Email string `sensitive:"data,knd=email"`
			}{},
		},
		{
			name: "option on dive",
			val: struct {
				Child struct{} `sensitive:"dive,kind=email"`
			}{},
		},
		{
			name: "kind on subject",
			val: struct {
				ID string `sensitive:"subjectID,kind=email"`
			}{},
		},
		{
			name: "two tag IDs",
			val: struct {
				Email string `sensitive:"data" pii:"dive"`
			}{},
		},
		{
			name: "option without value",
			val: struct {
				Email string `sensitive:"data,kind"`
			}{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := reflect.TypeOf(tc.val).Field(0).Tag
			payload, err := ParseTag(raw)
			if err == nil || payload != nil {
				t.Fatalf("ParseTag() = %+v, %v", payload, err)
			}
			_, scanErr := Scan(&struct {
				Email string `sensitive:"data,knd=email"`
			}{Email: "a@b.c"}, false)
			if tc.name == "unknown option" && !errors.Is(scanErr, ErrInvalidTagConfiguration) {
				t.Fatalf("Scan() err = %v", scanErr)
			}
		})
	}

	raw := reflect.StructTag(`sensitive:"subjectID,prefix=a=b"`)
	payload, err := ParseTag(raw)
	if err != nil {
		t.Fatal(err)
	}
	if payload.Options["prefix"] != "a=b" {
		t.Fatalf("prefix = %q", payload.Options["prefix"])
	}
}
