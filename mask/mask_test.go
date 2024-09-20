package mask

import (
	"testing"
)

func TestMask_Registry(t *testing.T) {
	kind := "foo"

	if _, found := Of(kind); found {
		t.Fatal("expect not to find mask", kind)
	}

	Register(kind, DefaultMasker(func(val string, _ ...func(*Config[struct{}])) (string, error) {
		return "***", nil
	}))

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
