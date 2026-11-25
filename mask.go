package sensitive

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"reflect"

	"github.com/ln80/struct-sensitive/internal/option"
	"github.com/ln80/struct-sensitive/mask"
	"github.com/mitchellh/copystructure"
)

// WithRegisteredMasks masks each field with the mask registered for its kind,
// including the predefined ones: `email`, `ipv4_addr`, `credit_card`,
// `fullname`. A field without a kind or a registered mask, or whose mask
// fails, gets [Redacted]; a failure is reported with the field path.
//
// Use [mask.Register] to add a mask. Use [mask.Override] to replace one.
func WithRegisteredMasks() RedactOption {
	return func(rc *redactConfig) { rc.redactFunc = registeredMasks(rc) }
}

func registeredMasks(rc *redactConfig) ReplaceFunc {
	return func(fr FieldReplace, val string) (string, error) {
		if fr.Kind == "" {
			return RedactDefaultFunc(fr, val)
		}
		m, ok := mask.Of(fr.Kind)
		if !ok {
			return RedactDefaultFunc(fr, val)
		}
		masked, err := m(val)
		if err != nil {
			rc.fieldErrs = append(rc.fieldErrs, fmt.Errorf("%s: %w", fr.Path, err))
			return RedactDefaultFunc(fr, val)
		}
		return masked, nil
	}
}

// Mask partially redacts sensitive data based on their type (aka kind).
//
// It is simply a facade function that calls [Redact] with [WithRegisteredMasks] option.
//
// Use [mask.Register] to add a mask. Use [mask.Override] to replace one,
// including a predefined mask.
func Mask(structPtr any, opts ...RedactOption) (err error) {
	defer catchPanic(&err)
	err = Redact(structPtr, append([]RedactOption{WithRegisteredMasks()}, opts...)...)
	return err
}

// ErrFailedToMaskCopy is returned by NewMaskedCopy, joined with the cause.
var ErrFailedToMaskCopy = errors.New("failed to mask copy")

// maskedOriginal holds the caller value behind an unexported type so a
// reflection dump that does not follow unexported values prints an address.
type maskedOriginal[T any] struct {
	v T
}

// Masked is a wrapper that contains both the original value and masked copy.
// Reveal is the only supported way to read the original value.
type Masked[T any] struct {
	original *maskedOriginal[T]
	value    T
}

// maskedCopyConfig is set by MaskedCopyOption.
type maskedCopyConfig struct {
	deepCopy bool
}

// MaskedCopyOption configures [NewMaskedCopy]. [WithoutDeepCopy] builds one.
type MaskedCopyOption func(*maskedCopyConfig)

// WithoutDeepCopy masks a shallow copy instead of a deep one. It is unsafe
// when the value contains pointer, slice, or map fields: those fields are
// shared with the caller, so Reveal and the caller can observe masked data.
func WithoutDeepCopy() MaskedCopyOption {
	return func(c *maskedCopyConfig) { c.deepCopy = false }
}

// NewMaskedCopy returns a new masked copy of the given value.
// It fails if it can't copy the value or the mask config is invalid.
//
// Reveal returns v, including its unexported fields. The masked value is a
// deep copy unless [WithoutDeepCopy] is set. T may be a struct or a pointer
// to a struct.
func NewMaskedCopy[T any](v T, opts ...MaskedCopyOption) (*Masked[T], error) {
	cfg := maskedCopyConfig{
		deepCopy: true,
	}
	option.Apply(&cfg, opts)

	if !cfg.deepCopy {
		masked := v
		if err := maskValue(&masked); err != nil {
			return nil, errors.Join(ErrFailedToMaskCopy, err)
		}
		return &Masked[T]{value: masked, original: &maskedOriginal[T]{v: v}}, nil
	}

	copied, err := copystructure.Copy(v)
	if err != nil {
		return nil, errors.Join(ErrFailedToMaskCopy, err)
	}
	masked := copied.(T)
	if err := maskValue(&masked); err != nil {
		return nil, errors.Join(ErrFailedToMaskCopy, err)
	}
	return &Masked[T]{value: masked, original: &maskedOriginal[T]{v: v}}, nil
}

// maskValue masks a struct or a pointer to a struct held in v.
func maskValue[T any](v *T) error {
	rv := reflect.ValueOf(v).Elem()
	if rv.Kind() == reflect.Pointer {
		if rv.IsNil() {
			return fmt.Errorf("%w '%v'", ErrUnsupportedType, nil)
		}
		return Mask(rv.Interface())
	}
	return Mask(v)
}

// MustMaskedCopy is like [NewMaskedCopy] but panics if it fails. Use it for
// values whose type is known to mask, such as package-level fixtures.
func MustMaskedCopy[T any](v T, opts ...MaskedCopyOption) *Masked[T] {
	copy, err := NewMaskedCopy(v, opts...)
	if err != nil {
		panic(err)
	}
	return copy
}

// Reveal returns the value passed to NewMaskedCopy.
// It is the only supported way to read that value back.
func (r Masked[T]) Reveal() T {
	if r.original == nil {
		var zero T
		return zero
	}
	return r.original.v
}

// Value returns the masked copy value
func (r Masked[T]) Value() T {
	return r.value
}

// LogValue implements slog.LogValuer
func (r Masked[T]) LogValue() slog.Value {
	return slog.AnyValue(r.value)
}

// String implements fmt.Stringer and returns the masked value.
func (r Masked[T]) String() string {
	return fmt.Sprintf("%+v", r.value)
}

// GoString implements fmt.GoStringer and returns the masked value.
func (r Masked[T]) GoString() string {
	return fmt.Sprintf("%#v", r.value)
}

// MarshalJSON implements json.Marshaler and encodes the masked value.
func (r Masked[T]) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.value)
}

// MarshalText implements encoding.TextMarshaler and encodes the masked value.
func (r Masked[T]) MarshalText() ([]byte, error) {
	return []byte(r.String()), nil
}
