package mask

import (
	"errors"
	"testing"
)

func TestMask_Registry(t *testing.T) {
	kind := "foo"

	if _, found := Of(kind); found {
		t.Fatal("expect not to find mask", kind)
	}

	if err := Register(kind, DefaultMasker(func(val string, _ ...func(*Config[struct{}])) (string, error) {
		return "***", nil
	})); err != nil {
		t.Fatal(err)
	}

	m, found := Of(kind)
	if !found {
		t.Fatal("expect to find mask", kind)
	}

	result, err := m("sensitive content")
	if err != nil {
		t.Fatal("expect err nil, got", err)
	}
	if result != "***" {
		t.Fatalf("want %s, got %s", "***", result)
	}
}

func TestRegisterRejectsNilAndDuplicate(t *testing.T) {
	if err := Register("", func(string) (string, error) { return "", nil }); err == nil {
		t.Fatal("empty kind err = nil")
	}
	if err := Register("nil_mask", nil); err == nil || !errors.Is(err, ErrNilMask) {
		t.Fatalf("nil mask err = %v", err)
	}
	kind := "register_once"
	fn := func(string) (string, error) { return "a", nil }
	if err := Register(kind, fn); err != nil {
		t.Fatal(err)
	}
	if err := Register(kind, fn); err == nil || !errors.Is(err, ErrMaskRegistered) {
		t.Fatalf("duplicate err = %v", err)
	}
	if err := Register("email", fn); err == nil || !errors.Is(err, ErrMaskRegistered) {
		t.Fatalf("builtin override err = %v", err)
	}
	if err := Override(kind, func(string) (string, error) { return "b", nil }); err != nil {
		t.Fatal(err)
	}
	m, found := Of(kind)
	if !found {
		t.Fatal("override was not stored")
	}
	out, err := m("x")
	if err != nil || out != "b" {
		t.Fatalf("Override result = %q, %v", out, err)
	}
}
