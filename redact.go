package sensitive

import (
	"errors"
	"strings"

	"github.com/ln80/struct-sensitive/internal/option"
)

var (
	ErrRedactFuncNotFound = errors.New("redact function not found")
)

// RedactConfig presents the configuration required by `sensitive.Redact`.
type RedactConfig struct {
	// RequireSubjectID force the subjectID resolution from the struct value.
	// This config is disabled by default.
	RequireSubjectID bool

	// RedactFunc overrides the default redaction function `RedactDefaultFunc`.
	RedactFunc ReplaceFunc
}

// Redact redacts sensitive data from struct field values by replacing each character with '*'.
//
// It returns an error if the value is not a struct pointer, the 'sensitive' tag is misconfigured,
// or if the redact function is nil.
//
// Optionally, you can override the default redact function by passing a custom one.
func Redact(structPtr any, opts ...func(*RedactConfig)) error {
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

	return accessor.Replace(cfg.RedactFunc)
}

func RedactDefaultFunc(_ FieldReplace, val string) (string, error) {
	return strings.Repeat("*", len(val)), nil
}
