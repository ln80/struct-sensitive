package mask

import (
	"errors"
	"strings"
	"unicode/utf8"

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

	// Use rune count for correct multi-byte character handling
	localRunes := []rune(parts[0])
	localRuneCount := utf8.RuneCountInString(parts[0])

	var local string
	if cfg.Kind.KeepFirstAndLastChar && localRuneCount > 2 {
		firstChar := string(localRunes[0])
		lastChar := string(localRunes[localRuneCount-1])
		middle := strings.Repeat(string([]rune{cfg.Symbol}), localRuneCount-2)
		local = firstChar + middle + lastChar
	} else {
		local = strings.Repeat(string([]rune{cfg.Symbol}), localRuneCount)
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
