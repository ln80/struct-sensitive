package mask

import (
	"errors"
	"strings"

	"github.com/ln80/struct-sensitive/internal/option"
)

type EmailConfig struct {
	MaskDomain bool // default false
}

func Email(email string, opts ...func(*Config[EmailConfig])) (string, error) {
	cfg := DefaultConfig(EmailConfig{
		MaskDomain: false,
	})
	option.Apply(&cfg, opts)

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "", errors.New("invalid email format")
	}

	local := strings.Repeat(string([]rune{cfg.Symbol}), len(parts[0]))

	domain := parts[1]
	if cfg.Kind.MaskDomain {
		var builder strings.Builder
		for _, ch := range domain {
			if ch == '.' {
				builder.WriteRune('.')
			} else {
				builder.WriteRune(cfg.Symbol)
			}
		}
		domain = builder.String()
	}

	return local + "@" + domain, nil
}

func init() {
	Register("email", DefaultMasker(Email))
}
