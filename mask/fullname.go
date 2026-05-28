package mask

import (
	"strings"
	"unicode/utf8"

	"github.com/ln80/struct-sensitive/internal/option"
)

type FullNameConfig struct {
}

// FullName masks a full name by revealing only the first character of the first and last words.
func FullName(name string, opts ...func(*Config[FullNameConfig])) (string, error) {
	cfg := DefaultConfig(FullNameConfig{})
	option.Apply(&cfg, opts)

	words := strings.Fields(name)

	var builder strings.Builder
	for i, word := range words {
		// Use rune count for correct multi-byte character handling
		runeCount := utf8.RuneCountInString(word)
		if i == 0 || i == len(words)-1 {
			builder.WriteRune([]rune(word)[0])
			builder.WriteString(strings.Repeat(string(cfg.Symbol), runeCount-1))
		} else {
			builder.WriteString(strings.Repeat(string(cfg.Symbol), runeCount))
		}
		if i != len(words)-1 {
			builder.WriteRune(' ')
		}
	}

	return builder.String(), nil
}

func init() {
	Register("fullname", DefaultMasker(FullName))
}
