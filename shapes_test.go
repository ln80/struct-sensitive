package sensitive

import (
	"errors"
	"reflect"
	"testing"
)

type Name string
type Blob []byte

// TestSupportedShapes pins docs/tag-format.md section 3: every accepted
// shape scans, every refused one fails, none is skipped.
func TestSupportedShapes(t *testing.T) {
	cases := []struct {
		name string
		val  any
		ok   bool
	}{
		{"data string", &struct {
			V string `pii:"data"`
		}{}, true},
		{"data named string", &struct {
			V Name `pii:"data"`
		}{}, true},
		{"data *string", &struct {
			V *string `pii:"data"`
		}{}, true},
		{"data []byte", &struct {
			V []byte `pii:"data"`
		}{}, true},
		{"data named []byte", &struct {
			V Blob `pii:"data"`
		}{}, true},
		{"data *[]byte", &struct {
			V *[]byte `pii:"data"`
		}{}, true},
		{"data []string", &struct {
			V []string `pii:"data"`
		}{}, true},
		{"data []*string", &struct {
			V []*string `pii:"data"`
		}{}, true},
		{"data [][]byte", &struct {
			V [][]byte `pii:"data"`
		}{}, true},
		{"data int", &struct {
			V int `pii:"data"`
		}{}, false},
		{"data []rune", &struct {
			V []rune `pii:"data"`
		}{}, false},
		{"data **string", &struct {
			V **string `pii:"data"`
		}{}, false},
		{"data map", &struct {
			V map[string]string `pii:"data"`
		}{}, false},
		{"data struct", &struct {
			V Address `pii:"data"`
		}{}, false},
		{"subject string", &struct {
			ID string `pii:"subjectID"`
		}{}, true},
		{"subject *string", &struct {
			ID *string `pii:"subjectID"`
		}{}, true},
		{"subject []byte", &struct {
			ID []byte `pii:"subjectID"`
		}{}, true},
		{"subject int", &struct {
			ID int `pii:"subjectID"`
		}{}, false},
		{"subject []string", &struct {
			ID []string `pii:"subjectID"`
		}{}, false},
		{"dive struct", &struct {
			V Address `pii:"dive"`
		}{}, true},
		{"dive *struct", &struct {
			V *Address `pii:"dive"`
		}{}, true},
		{"dive []struct", &struct {
			V []Address `pii:"dive"`
		}{}, true},
		{"dive []*struct", &struct {
			V []*Address `pii:"dive"`
		}{}, true},
		{"dive map", &struct {
			V map[string]Address `pii:"dive"`
		}{}, true},
		{"dive map of pointers", &struct {
			V map[string]*Address `pii:"dive"`
		}{}, true},
		{"dive string", &struct {
			V string `pii:"dive"`
		}{}, false},
		{"dive []string", &struct {
			V []string `pii:"dive"`
		}{}, false},
		{"unexported data", &struct {
			v string `pii:"data"`
		}{}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Scan(tc.val)
			if tc.ok && err != nil {
				t.Fatalf("Scan() err = %v, want accepted", err)
			}
			if !tc.ok && !errors.Is(err, ErrInvalidTagConfiguration) {
				t.Fatalf("Scan() err = %v, want ErrInvalidTagConfiguration", err)
			}
			found, err := Check(tc.val)
			if tc.ok != (err == nil) {
				t.Fatalf("Check() = %v, %v: disagrees with Scan", found, err)
			}
		})
	}
}

// Every accepted data shape is visited and written back.
func TestRedactEveryShape(t *testing.T) {
	type rec struct {
		ID     []byte              `pii:"subjectID"`
		S      Name                `pii:"data"`
		P      *string             `pii:"data"`
		B      Blob                `pii:"data"`
		PB     *[]byte             `pii:"data"`
		SS     []string            `pii:"data"`
		SP     []*string           `pii:"data"`
		BB     [][]byte            `pii:"data"`
		Nil    *string             `pii:"data"`
		NilEl  []*string           `pii:"data"`
		Nested map[string]*Address `pii:"dive"`
	}
	r := rec{
		ID: []byte("u1"), S: "s", P: ptr("p"), B: Blob("b"), PB: ptr([]byte("pb")),
		SS: []string{"a", ""}, SP: []*string{ptr("x")}, BB: [][]byte{[]byte("y")},
		NilEl:  []*string{nil},
		Nested: map[string]*Address{"home": {Street: "st"}, "none": nil},
	}
	var subjects []string
	s, err := Scan(&r, WithRequireSubject())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Replace(func(fr FieldReplace, val string) (string, error) {
		subjects = append(subjects, fr.SubjectID)
		return RedactDefaultFunc(fr, val)
	}); err != nil {
		t.Fatal(err)
	}
	want := rec{
		ID: []byte("u1"), S: Redacted, P: ptr(Redacted), B: Blob(Redacted), PB: ptr([]byte(Redacted)),
		SS: []string{Redacted, ""}, SP: []*string{ptr(Redacted)}, BB: [][]byte{[]byte(Redacted)},
		NilEl:  []*string{nil},
		Nested: map[string]*Address{"home": {Street: Redacted}, "none": nil},
	}
	if !reflect.DeepEqual(r, want) {
		t.Fatalf("got %+v\nwant %+v", r, want)
	}
	for _, sub := range subjects {
		if sub != "u1" {
			t.Fatalf("a field was visited under subject %q", sub)
		}
	}
}

func TestMaskedCopyOptions(t *testing.T) {
	orig := &Profile{ID: "u1", Email: "alice@example.com", Fullname: "Alice"}
	shallow, err := NewMaskedCopy(*orig, WithoutDeepCopy())
	if err != nil {
		t.Fatal(err)
	}
	if shallow.Value().Fullname != Redacted || shallow.Reveal().Fullname != "Alice" {
		t.Fatalf("shallow copy: value %+v, reveal %+v", shallow.Value(), shallow.Reveal())
	}
	if m := MustMaskedCopy(orig); m.Value().Fullname != Redacted || orig.Fullname != "Alice" {
		t.Fatalf("MustMaskedCopy: value %+v, original %+v", m.Value(), orig)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Fatal("MustMaskedCopy of a nil pointer did not panic")
			}
		}()
		_ = MustMaskedCopy[*Profile](nil)
	}()
	var zero Masked[Profile]
	if !reflect.DeepEqual(zero.Reveal(), Profile{}) {
		t.Fatal("a zero Masked reveals something")
	}
}

func TestFieldTag(t *testing.T) {
	if p := MustFieldTag(Profile{}, "Email"); p.String() != `sensitive:"data,kind=email"` || p.Options.Get("replace") != "" {
		t.Fatalf("MustFieldTag() = %v", p)
	}
	if p, err := FieldTag(&Profile{}, "Fullname"); err != nil || p.Name != "data" {
		t.Fatalf("FieldTag(*Profile) = %v, %v", p, err)
	}
	for name, call := range map[string]func() (*TagPayload, error){
		"nil":     func() (*TagPayload, error) { return FieldTag(nil, "X") },
		"string":  func() (*TagPayload, error) { return FieldTag("x", "X") },
		"missing": func() (*TagPayload, error) { return FieldTag(Profile{}, "Nope") },
	} {
		if _, err := call(); err == nil {
			t.Errorf("FieldTag(%s): expect an error", name)
		}
	}
	defer func() {
		if recover() == nil {
			t.Fatal("MustFieldTag of an untagged field did not panic")
		}
	}()
	_ = MustFieldTag(struct{ X string }{}, "X")
}

// Subjects reached through embedded pointers, byte slices and prefixes.
func TestSubjectEdges(t *testing.T) {
	type Owner struct {
		ID *[]byte `pii:"subjectID,prefix=usr_"`
	}
	type rec struct {
		*Owner
		Email string `pii:"data"`
	}
	r := rec{Owner: &Owner{ID: ptr([]byte("1"))}, Email: "a@b.c"}
	s, err := Scan(&r, WithRequireSubject())
	if err != nil {
		t.Fatal(err)
	}
	if id, ok := s.SubjectID(); !ok || id != "usr_1" {
		t.Fatalf("SubjectID() = %q, %v", id, ok)
	}

	// A nil embedded pointer holds no subject: the data has none.
	if _, err := Scan(&rec{Email: "a@b.c"}, WithRequireSubject()); !errors.Is(err, ErrSubjectIDNotFound) {
		t.Fatalf("nil owner: err = %v, want ErrSubjectIDNotFound", err)
	}
	// A nil byte slice is an empty subject.
	if _, err := Scan(&rec{Owner: &Owner{}, Email: "a@b.c"}, WithRequireSubject()); !errors.Is(err, ErrSubjectIDNotFound) {
		t.Fatalf("nil ID: err = %v, want ErrSubjectIDNotFound", err)
	}
	// Without the requirement, data without a subject is still visited.
	if err := Redact(&rec{Email: "a@b.c"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Scan(&r, WithSubjectMode(SubjectMode(9))); !errors.Is(err, ErrInvalidTagConfiguration) {
		t.Fatalf("unknown subject mode: err = %v", err)
	}
}
