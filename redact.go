package sensitive

import (
	"errors"

	"github.com/ln80/struct-sensitive/internal/option"
)

var (
	ErrRedactFuncNotFound = errors.New("redact function not found")
)

// RedactConfig holds the configuration for [Redact].
type RedactConfig struct {
	// RequireSubjectID force the subjectID resolution from the struct value.
	// This config is disabled by default.
	RequireSubjectID bool

	// RedactFunc overrides the default redaction function `RedactDefaultFunc`.
	RedactFunc ReplaceFunc

	// fieldErrs collects per-field failures that were replaced with full redaction.
	fieldErrs []error
}

// Redact redacts sensitive data from struct field values by replacing each character with '*'.
//
// It returns an error if the value is not a struct pointer, the 'sensitive' tag is misconfigured,
// or if the redact function is nil.
//
// Optionally, you can override the default redact function by passing a custom one.
func Redact(structPtr any, opts ...func(*RedactConfig)) (err error) {
	defer catchPanic(&err)
	cfg := RedactConfig{
		RedactFunc: RedactDefaultFunc,
	}
	option.Apply(&cfg, opts)

	if cfg.RedactFunc == nil {
		return ErrRedactFuncNotFound
	}

	accessor, err := Scan(structPtr, cfg.RequireSubjectID)
	if err != nil {
		return err
	}

	if !accessor.HasSensitive() {
		return nil
	}

	if err = accessor.Replace(cfg.RedactFunc); err != nil {
		return err
	}
	return errors.Join(cfg.fieldErrs...)
}

// Redacted is the fixed placeholder written by RedactDefaultFunc.
// It does not preserve the length of the original value.
const Redacted = "***"

func RedactDefaultFunc(_ FieldReplace, val string) (string, error) {
	if val == "" {
		return "", nil
	}
	return Redacted, nil
}
