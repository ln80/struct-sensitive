package sensitive

import (
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
			if !tc.ok {
				payload := ParseTag(rawTag)
				if payload != nil {
					t.Fatal("expect payload be nil got", payload)
				}
				return
			}
			payload := ParseTag(rawTag)
			if want, got := tc.want, payload; !reflect.DeepEqual(want, got) {
				t.Fatalf("want %+v, got %+v", want, got)
			}
			if want, got := string(rawTag), payload.Marshal(); want != got {
				t.Fatalf("want '%v', got '%v'", want, got)
			}
		})
	}
}
