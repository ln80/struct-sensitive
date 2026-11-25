package mask

import (
	"errors"
	"fmt"
	"sync"
)

var (
	// ErrNilMask is returned when a mask function is nil.
	ErrNilMask = errors.New("nil mask")
	// ErrMaskRegistered is returned when Register is asked to replace a kind.
	ErrMaskRegistered = errors.New("mask already registered")
)

// Config is the generic mask config required by any registered mask.
//
// The Type parameter represents the mask specific config.
type Config[T any] struct {
	Symbol rune
	Kind   T
}

// DefaultConfig wraps the specific mask config and returns a generic one with defaults.
func DefaultConfig[T any](t T) Config[T] {
	return Config[T]{
		Symbol: '*',
		Kind:   t,
	}
}

// Masker is the function type that masks must satisfy.
type Masker[T any] func(val string, opts ...func(*Config[T])) (string, error)

// Func masks one value. It is what the registry holds: [Register],
// [Override] and [Of] take and return it.
type Func func(val string) (string, error)

// DefaultMasker returns m with its default config, as a [Func].
func DefaultMasker[T any](m Masker[T]) Func {
	return func(val string) (string, error) { return m(val) }
}

var (
	maskRegistry map[string]Func = make(map[string]Func)
	maskMu       sync.RWMutex
)

// Register adds a default masker for kind.
// It rejects a nil function, an empty kind, and a kind that is already registered.
// Use Override to replace a mask, including a predefined one.
func Register(kind string, m Func) error {
	return register(kind, m, false)
}

// Override sets the mask for kind, replacing one that is already registered.
// It rejects a nil function and an empty kind.
func Override(kind string, m Func) error {
	return register(kind, m, true)
}

func register(kind string, m Func, override bool) error {
	if m == nil {
		return ErrNilMask
	}
	if kind == "" {
		return errors.New("empty mask kind")
	}
	maskMu.Lock()
	defer maskMu.Unlock()
	if _, exists := maskRegistry[kind]; exists && !override {
		return fmt.Errorf("%w: %s", ErrMaskRegistered, kind)
	}
	maskRegistry[kind] = m
	return nil
}

func mustRegister(kind string, m Func) {
	if err := Register(kind, m); err != nil {
		panic(err)
	}
}

// Of returns the mask registered for kind.
func Of(kind string) (m Func, found bool) {
	// Read-only access: use RLock to allow concurrent mask lookups
	maskMu.RLock()
	defer maskMu.RUnlock()

	m, found = maskRegistry[kind]
	return
}
