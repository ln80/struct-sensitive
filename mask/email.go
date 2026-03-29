package mask

import (
	"errors"
	"strings"

	"github.com/ln80/struct-sensitive/internal/option"
)

type EmailConfig struct {
	MaskDomain           bool // default false
	KeepFirstAndLastChar bool // default false
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

	var local string
	if cfg.Kind.KeepFirstAndLastChar && len(parts[0]) > 2 {
		// Keep first and last character, mask the rest
		firstChar := string([]rune(parts[0])[0])
		lastChar := string([]rune(parts[0])[len([]rune(parts[0]))-1])
		middle := strings.Repeat(string([]rune{cfg.Symbol}), len([]rune(parts[0]))-2)
		local = firstChar + middle + lastChar
	} else {
		// Mask the entire local part
		local = strings.Repeat(string([]rune{cfg.Symbol}), len(parts[0]))
	}

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
