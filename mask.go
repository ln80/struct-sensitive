package sensitive

import "github.com/ln80/struct-sensitive/mask"

// WithRegisteredMasks returns an option that force redaction using the registered masks,
// including the predefined one e.g. `email`, `ipv4_addr`, `credit_card`.
//
// Use [RegisterMask] to override or register new masks per sensitive data kind.
func WithRegisteredMasks(rc *RedactConfig) {
	rc.RedactFunc = func(fr FieldReplace, val string) (string, error) {
		if fr.Kind == "" {
			return DefaultRedactFunc(fr, val)
		}
		m, ok := mask.Of(fr.Kind)
		if !ok {
			return DefaultRedactFunc(fr, val)
		}
		return m(val)
	}
}

// Mask is a facade function that calls [Redact] with [WithRegisteredMasks] option.
func Mask(structPtr any, opts ...func(*RedactConfig)) error {
	return Redact(structPtr, append(opts, WithRegisteredMasks)...)
}
