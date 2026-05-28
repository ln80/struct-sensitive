package sensitive

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"

	"github.com/ln80/struct-sensitive/internal/option"
	"github.com/ln80/struct-sensitive/mask"
	"github.com/mitchellh/copystructure"
)

// WithRegisteredMasks returns an option that force redaction using the registered masks,
// including the predefined one e.g. `email`, `ipv4_addr`, `credit_card`.
//
// Use [mask.Register] to override or register new masks.
func WithRegisteredMasks(rc *RedactConfig) {
	rc.RedactFunc = func(fr FieldReplace, val string) (string, error) {
		if fr.Kind == "" {
			return RedactDefaultFunc(fr, val)
		}
		m, ok := mask.Of(fr.Kind)
		if !ok {
			return RedactDefaultFunc(fr, val)
		}
		return m(val)
	}
}

// Mask partially redacts sensitive data based on their type (aka kind).
//
// It is simply a facade function that calls [Redact] with [WithRegisteredMasks] option.
//
// Use [mask.Register] to register additional masks.
func Mask(structPtr any, opts ...func(*RedactConfig)) error {
	return Redact(structPtr, append([]func(*RedactConfig){WithRegisteredMasks}, opts...)...)
}

var (
	ErrFailedToMaskCopy = errors.New("failed to mask copy")
)

// Masked is a wrapper that contains both the original value and masked copy
type Masked[T any] struct {
	original T
	value    T
}

type MaskedCopyConfig struct {
	// DeepCopy controls whether the original value is deep-copied before masking.
	// Defaults to true. Setting to false is unsafe when the struct contains pointer,
	// slice, or map fields, as Reveal() may return partially masked data.
	DeepCopy bool
}

// NewMaskedCopy returns a new masked copy of the given value.
// It fails if it can't copy the value or the mask config is invalid.
func NewMaskedCopy[T any](v T, opts ...func(*MaskedCopyConfig)) (*Masked[T], error) {
	cfg := MaskedCopyConfig{
		DeepCopy: true,
	}
	option.Apply(&cfg, opts)

	masked := v
	if cfg.DeepCopy {
		// Deep-copy the original to prevent shared pointers between original and masked values.
		// Without this, masking through shared *string/slice/map fields corrupts the original.
		orig, err := copystructure.Copy(v)
		if err != nil {
			return nil, errors.Join(ErrFailedToMaskCopy, err)
		}
		if err := Mask(&masked); err != nil {
			return nil, errors.Join(ErrFailedToMaskCopy, err)
		}
		return &Masked[T]{value: masked, original: orig.(T)}, nil
	}

	if err := Mask(&masked); err != nil {
		return nil, errors.Join(ErrFailedToMaskCopy, err)
	}
	return &Masked[T]{value: masked, original: v}, nil
}

// MaskedCopy returns a masked copy of the given value.
// It panics in case of failure.
func MaskedCopy[T any](v T, opts ...func(*MaskedCopyConfig)) *Masked[T] {
	copy, err := NewMaskedCopy(v, opts...)
	if err != nil {
		panic(err)
	}
	return copy
}

// Reveal reveals the original value without applying masks
func (r Masked[T]) Reveal() T {
	return r.original
}

// Value returns the masked copy value
func (r Masked[T]) Value() T {
	return r.value
}

// LogValue implements slog.LogValuer
func (r Masked[T]) LogValue() slog.Value {
	return slog.AnyValue(r.value)
}

// String implements fmt.Stringer
func (r Masked[T]) String() string {
	return fmt.Sprintf("%+v", r.value)
}

// MarshalJSON implements json.Marshaler
func (r Masked[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.value)
}
