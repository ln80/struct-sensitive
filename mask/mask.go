package mask

import "sync"

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

// Masker presents the function type that masks must satisfy.
type Masker[T any] func(val string, opts ...func(*Config[T])) (string, error)

// defaultMasker is a masker that doesn't support options
type defaultMasker func(val string) (string, error)

// DefaultMasker takes a masker and return the default masker associated with.
func DefaultMasker[T any](m Masker[T]) defaultMasker {
	return func(val string) (string, error) { return m(val) }
}

var (
	maskRegistry map[string]defaultMasker = make(map[string]defaultMasker)
	maskMu       sync.RWMutex
)

// Register registers a default masker to handle a specific kind of sensitive data.
func Register(kind string, m defaultMasker) {
	maskMu.Lock()
	defer maskMu.Unlock()

	maskRegistry[kind] = m
}

// Of returns the specific default masker of the given kind.
func Of(kind string) (m defaultMasker, found bool) {
	maskMu.Lock()
	defer maskMu.Unlock()

	m, found = maskRegistry[kind]
	return
}
