package sensitive

import (
	"reflect"
	"strings"
	"testing"
)

// FuzzParseTag: ParseTag never panics, and a tag it accepts marshals back to
// a tag that parses to the same payload.
func FuzzParseTag(f *testing.F) {
	for _, s := range []string{
		`pii:"data"`, `sensitive:"data,kind=email,replace=[x]"`, `sens:"subjectID,prefix=a=b"`,
		`pii:"dive"`, `pii:"datum"`, `pii:"data,kind=a,kind=b"`, `pii:""`, `pii:"data" sens:"dive"`,
		`pii:" data , kind = email "`, `pii:"data,"`, `json:"x" pii:"data"`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		p, err := ParseTag(reflect.StructTag(raw))
		if err != nil || p == nil {
			return
		}
		again, err := ParseTag(reflect.StructTag(p.Marshal()))
		if err != nil {
			// A value holding a quote or a comma cannot be written back.
			for _, v := range p.Options {
				if strings.ContainsAny(v, `",\`) {
					return
				}
			}
			t.Fatalf("Marshal() of an accepted tag does not parse: %v", err)
		}
		if again.Name != p.Name || !reflect.DeepEqual(again.Options, p.Options) {
			t.Fatalf("round trip changed the tag: %v -> %v", p, again)
		}
	})
}

type fuzzMember struct {
	ID    string   `pii:"subjectID"`
	Email string   `pii:"data,kind=email"`
	Tags  []string `pii:"data"`
}

type fuzzGroup struct {
	ID      []byte                 `pii:"subjectID"`
	Name    *string                `pii:"data,kind=fullname"`
	Card    string                 `pii:"data,kind=credit_card"`
	IP      string                 `pii:"data,kind=ipv4_addr"`
	Members []*fuzzMember          `pii:"dive"`
	ByKey   map[string]*fuzzMember `pii:"dive"`
}

// FuzzMask: Mask never panics and never leaves a non-empty data value as it
// was: each one is masked or redacted, whatever the input.
func FuzzMask(f *testing.F) {
	f.Add("g1", "Alice Doe", "4111-1111-1111-1111", "10.0.0.1", "u1", "alice@example.com", "x")
	f.Add("", "", "", "", "", "", "")
	f.Add("g", "a", "not a card", "999.1.1.1", "", "no-at-sign", "y")
	f.Add("0", "0", "0", "0", "0", "@", "0") // an empty local part masked to itself
	f.Fuzz(func(t *testing.T, gid, name, card, ip, mid, email, tag string) {
		n := name // Mask writes through the pointer: keep name as the input
		g := fuzzGroup{
			ID: []byte(gid), Name: &n, Card: card, IP: ip,
			Members: []*fuzzMember{{ID: mid, Email: email, Tags: []string{tag}}, nil},
			ByKey:   map[string]*fuzzMember{"k": {ID: mid, Email: email}},
		}
		_ = Mask(&g)
		check := func(field, in, out string) {
			// An input made of the mask symbol may mask to itself.
			if in != "" && !strings.Contains(in, "*") && out == in {
				t.Fatalf("%s left as it was", field)
			}
		}
		check("Name", name, *g.Name)
		check("Card", card, g.Card)
		check("IP", ip, g.IP)
		check("Members[0].Email", email, g.Members[0].Email)
		check("Members[0].Tags[0]", tag, g.Members[0].Tags[0])
		check("ByKey[k].Email", email, g.ByKey["k"].Email)
		if string(g.ID) != gid || g.Members[0].ID != mid {
			t.Fatal("a subject was changed")
		}
	})
}

// FuzzScanSubjects: Scan never panics, and in SingleSubject mode it accepts
// a value only when every data field carries one subject.
func FuzzScanSubjects(f *testing.F) {
	f.Add("u1", "u1", "u2")
	f.Add("", "", "")
	f.Add("a", "b", "")
	f.Fuzz(func(t *testing.T, root, m1, m2 string) {
		g := fuzzGroup{
			ID:      []byte(root),
			Name:    ptr("n"),
			Members: []*fuzzMember{{ID: m1, Email: "e"}, {ID: m2, Email: "e"}},
		}
		s, err := Scan(&g, WithSubjectMode(SingleSubject))
		if err != nil {
			return
		}
		subjects, err := s.Subjects()
		if err != nil {
			return
		}
		if len(subjects) > 1 {
			t.Fatalf("SingleSubject accepted subjects %q", subjects)
		}
	})
}
