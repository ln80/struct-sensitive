package mask

import (
	"strings"

	"github.com/ln80/struct-sensitive/internal/option"
)

type FullNameConfig struct {
}

// FullName masks a full name in the format "J*** ***** ***** D**".
func FullName(name string, opts ...func(*Config[FullNameConfig])) (string, error) {
	cfg := DefaultConfig(FullNameConfig{})
	option.Apply(&cfg, opts)

	// Split name into words
	words := strings.Fields(name)

	// Mask all words except the first and last
	var builder strings.Builder
	for i, word := range words {
		if i == 0 || i == len(words)-1 {
			builder.WriteRune([]rune(word)[0])
			builder.WriteString(strings.Repeat(string(cfg.Symbol), len(word)-1))
		} else { // Middle words
			builder.WriteString(strings.Repeat(string(cfg.Symbol), len(word)))
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
