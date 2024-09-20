package sensitive

import (
	"errors"
	"strings"
)

var (
	ErrRedactFuncNotFound = errors.New("redact function not found")
)

func DefaultRedactFunc(_ FieldReplace, val string) (string, error) {
	return strings.Repeat("*", len(val)), nil
}

// RedactConfig presents the configuration required by `sensitive.Redact`.
type RedactConfig struct {
	// RequireSubjectID force the subjectID resolution from the struct value.
	// This config is disabled by default.
	RequireSubjectID bool

	// RedactFunc overrides the default redaction function `DefaultRedactFunc`.
	RedactFunc ReplaceFunc
}

// Redact does redact sensitive data from the struct field values
// by replacing each character with '*'.
//
// It fails if the value isn't a struct pointer, `sens` tag is misconfigured,
// or the redact function is nil.
//
// Optionally, it accepts overriding the default redact function.
func Redact(structPtr any, opts ...func(*RedactConfig)) error {
	cfg := RedactConfig{
		RedactFunc: DefaultRedactFunc,
	}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&cfg)
	}
	if cfg.RedactFunc == nil {
		return ErrRedactFuncNotFound
	}

	sensitiveStruct, err := Scan(structPtr, cfg.RequireSubjectID)
	if err != nil {
		return err
	}

	if !sensitiveStruct.typ.hasSensitive {
		return nil
	}

	return sensitiveStruct.Replace(cfg.RedactFunc)
}
