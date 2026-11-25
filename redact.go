package sensitive

import (
	"errors"

	"github.com/ln80/struct-sensitive/internal/option"
)

// redactConfig is set by RedactOption.
type redactConfig struct {
	redactFunc ReplaceFunc

	// fieldErrs collects per-field failures that were replaced with full redaction.
	fieldErrs []error
}

// RedactOption configures [Redact] and [Mask]. [WithRedactFunc] and
// [WithRegisteredMasks] build them.
type RedactOption func(*redactConfig)

// WithRedactFunc replaces [RedactDefaultFunc] with fn. A nil fn keeps the
// default.
func WithRedactFunc(fn ReplaceFunc) RedactOption {
	return func(c *redactConfig) {
		if fn != nil {
			c.redactFunc = fn
		}
	}
}

// Redact replaces every sensitive data field value with [Redacted].
//
// It returns an error if the value is not a struct pointer or the 'sensitive'
// tag is misconfigured. [WithRedactFunc] replaces the redaction.
func Redact(structPtr any, opts ...RedactOption) (err error) {
	defer catchPanic(&err)
	cfg := redactConfig{
		redactFunc: RedactDefaultFunc,
	}
	option.Apply(&cfg, opts)

	accessor, err := Scan(structPtr)
	if err != nil {
		return err
	}

	if !accessor.HasSensitive() {
		return nil
	}

	if err = accessor.Replace(cfg.redactFunc); err != nil {
		return err
	}
	return errors.Join(cfg.fieldErrs...)
}

// Redacted is the fixed placeholder written by RedactDefaultFunc.
// It does not preserve the length of the original value.
const Redacted = "***"

// RedactDefaultFunc replaces a non-empty value with [Redacted]. It is the
// [ReplaceFunc] Redact uses by default.
func RedactDefaultFunc(_ FieldReplace, val string) (string, error) {
	if val == "" {
		return "", nil
	}
	return Redacted, nil
}
