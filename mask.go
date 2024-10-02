package sensitive

import "github.com/ln80/struct-sensitive/mask"

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
	return Redact(structPtr, append(opts, WithRegisteredMasks)...)
}
