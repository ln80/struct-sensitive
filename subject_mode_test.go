package sensitive

import (
	"errors"
	"slices"
	"testing"
)

// Shapes shared by the subject-mode tests. Each type is used by one shape so
// the type cache cannot hide a difference between tests.

type modeAuthor struct {
	Subject string `sensitive:"subjectID"`
	Email   string `sensitive:"data"`
}

// A secret event: the secret owns the payload, the embedded author owns the email.
type modeSecretEvent struct {
	ID string `sensitive:"subjectID"`
	modeAuthor
	Payload string `sensitive:"data"`
}

type modeTokenOnly struct {
	Subject string `sensitive:"subjectID"`
	Token   string
}

// The same event once the author is only a token: its subjectID governs no data.
type modeTokenEvent struct {
	ID string `sensitive:"subjectID"`
	modeTokenOnly
	Payload string `sensitive:"data"`
}

type modeDevice struct {
	IP string `sensitive:"data"`
}

type modeViewer struct {
	Subject string `sensitive:"subjectID"`
	Email   string `sensitive:"data"`
}

// A view event: no subject of its own, one viewer, details inherit the viewer.
type modeViewEvent struct {
	Secret  string
	Viewer  modeViewer `sensitive:"dive"`
	Details modeDevice `sensitive:"dive"`
}

type modeMember struct {
	ID    string `sensitive:"subjectID"`
	Email string `sensitive:"data"`
}

type modeGroup struct {
	Name    string
	Members []modeMember `sensitive:"dive"`
}

type modeNode struct {
	ID       string     `sensitive:"subjectID"`
	Email    string     `sensitive:"data"`
	Children []modeNode `sensitive:"dive"`
}

type modeIdent struct {
	ID string `sensitive:"subjectID"`
}

// An embed that only provides the subject: promoted, one declaration.
type modePromoted struct {
	modeIdent
	Email string `sensitive:"data"`
}

func single() func(*ScanConfig) { return WithSubjectMode(SingleSubject) }

func subjectsOf(t *testing.T, s Struct) map[string]string {
	t.Helper()
	got := map[string]string{}
	if err := s.Replace(func(fr FieldReplace, val string) (string, error) {
		got[fr.Path] = fr.SubjectID
		return val, nil
	}); err != nil {
		t.Fatal(err)
	}
	return got
}

func TestSubjectModeDefaultIsMultiple(t *testing.T) {
	in := &modeSecretEvent{ID: "secret", modeAuthor: modeAuthor{Subject: "author", Email: "a@b.c"}, Payload: "body"}
	s, err := Scan(in, true)
	if err != nil {
		t.Fatal(err)
	}
	got := subjectsOf(t, s)
	if got["Payload"] != "secret" || got["modeAuthor.Email"] != "author" {
		t.Fatalf("subjects = %v", got)
	}
	subs, err := s.Subjects()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(subs, []string{"author", "secret"}) {
		t.Fatalf("Subjects() = %v", subs)
	}
}

func TestSingleSubjectRejectsSecondDeclaration(t *testing.T) {
	// Rejected on the type, even when both subjects hold the same value.
	for _, author := range []string{"author", "secret"} {
		in := &modeSecretEvent{ID: "secret", modeAuthor: modeAuthor{Subject: author, Email: "a@b.c"}, Payload: "body"}
		_, err := Scan(in, true, single())
		if !errors.Is(err, ErrMultipleSubjectID) {
			t.Fatalf("author %q: err = %v, want ErrMultipleSubjectID", author, err)
		}
		if in.Payload != "body" || in.Email != "a@b.c" {
			t.Fatal("Scan changed the value")
		}
	}
}

func TestSingleSubjectIgnoresSubjectWithoutData(t *testing.T) {
	in := &modeTokenEvent{ID: "secret", modeTokenOnly: modeTokenOnly{Subject: "author", Token: "tok"}, Payload: "body"}
	s, err := Scan(in, true, single())
	if err != nil {
		t.Fatal(err)
	}
	if s.SubjectID() != "secret" {
		t.Fatalf("SubjectID() = %q", s.SubjectID())
	}
	if got := subjectsOf(t, s); got["Payload"] != "secret" {
		t.Fatalf("subjects = %v", got)
	}
}

func TestSingleSubjectNestedOwnerAndInheritedDetails(t *testing.T) {
	in := &modeViewEvent{Secret: "s1", Viewer: modeViewer{Subject: "viewer", Email: "v@x.io"}, Details: modeDevice{IP: "9.9.9.9"}}
	s, err := Scan(in, true, single())
	if err != nil {
		t.Fatal(err)
	}
	if s.SubjectID() != "viewer" {
		t.Fatalf("SubjectID() = %q", s.SubjectID())
	}
	got := subjectsOf(t, s)
	if got["Viewer.Email"] != "viewer" || got["Details.IP"] != "viewer" {
		t.Fatalf("subjects = %v", got)
	}
}

func TestSingleSubjectPromotedEmbedIsOneDeclaration(t *testing.T) {
	s, err := Scan(&modePromoted{modeIdent: modeIdent{ID: "u1"}, Email: "a@b.c"}, true, single())
	if err != nil {
		t.Fatal(err)
	}
	if s.SubjectID() != "u1" {
		t.Fatalf("SubjectID() = %q", s.SubjectID())
	}
}

func TestSingleSubjectSliceElementsMustAgree(t *testing.T) {
	same := &modeGroup{Members: []modeMember{{ID: "u1", Email: "a@x"}, {ID: "u1", Email: "b@x"}}}
	s, err := Scan(same, true, single())
	if err != nil {
		t.Fatal(err)
	}
	if s.SubjectID() != "u1" {
		t.Fatalf("SubjectID() = %q", s.SubjectID())
	}

	differ := &modeGroup{Members: []modeMember{{ID: "u1", Email: "a@x"}, {ID: "u2", Email: "b@x"}}}
	if _, err := Scan(differ, true, single()); !errors.Is(err, ErrMultipleSubjectID) {
		t.Fatalf("err = %v, want ErrMultipleSubjectID", err)
	}
	// The default mode keeps each element's own subject.
	s, err = Scan(differ, true)
	if err != nil {
		t.Fatal(err)
	}
	if got := subjectsOf(t, s); got["Members[0].Email"] != "u1" || got["Members[1].Email"] != "u2" {
		t.Fatalf("subjects = %v", got)
	}
}

func TestSingleSubjectRejectsRecursiveSubjects(t *testing.T) {
	in := &modeNode{ID: "u1", Email: "a@x", Children: []modeNode{{ID: "u1", Email: "b@x"}}}
	if _, err := Scan(in, true, single()); !errors.Is(err, ErrMultipleSubjectID) {
		t.Fatalf("err = %v, want ErrMultipleSubjectID", err)
	}
	if _, err := Scan(in, true); err != nil {
		t.Fatalf("default mode: %v", err)
	}
}

func TestSubjectsReportsMissingSubject(t *testing.T) {
	s, err := Scan(&modeViewEvent{Details: modeDevice{IP: "1.2.3.4"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Subjects(); !errors.Is(err, ErrSubjectIDNotFound) {
		t.Fatalf("Subjects() err = %v, want ErrSubjectIDNotFound", err)
	}
}

func TestSubjectsWithoutSensitiveData(t *testing.T) {
	type plain struct{ Name string }
	s, err := Scan(&plain{Name: "x"}, false, single())
	if err != nil {
		t.Fatal(err)
	}
	subs, err := s.Subjects()
	if err != nil || len(subs) != 0 {
		t.Fatalf("Subjects() = %v, %v", subs, err)
	}
}

func TestUnknownSubjectMode(t *testing.T) {
	_, err := Scan(&modePromoted{}, false, WithSubjectMode(SubjectMode(7)))
	if !errors.Is(err, ErrInvalidTagConfiguration) {
		t.Fatalf("err = %v", err)
	}
}
