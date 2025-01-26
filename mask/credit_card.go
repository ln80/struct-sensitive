package mask

import (
	"errors"
	"strings"

	"github.com/ln80/struct-sensitive/internal/option"
)

type CreditCardConfig struct {
	MaskBankIdentifier bool // default false
}

func CreditCard(cardNumber string, opts ...func(*Config[CreditCardConfig])) (string, error) {
	cfg := DefaultConfig(CreditCardConfig{
		MaskBankIdentifier: false,
	})
	option.Apply(&cfg, opts)

	formatCardNumber := func(cardNumber string, groupings []int) string {
		totalLength := len(cardNumber)
		formattedLength := totalLength + len(groupings) - 1

		result := make([]rune, formattedLength)
		pos := 0
		index := 0

		for _, group := range groupings {
			if pos >= totalLength {
				break
			}

			if index > 0 {
				result[index] = ' '
				index++
			}

			end := pos + group
			if end > totalLength {
				end = totalLength
			}

			for i := pos; i < end; i++ {
				result[index] = rune(cardNumber[i])
				index++
			}

			pos += group
		}

		return string(result)
	}

	cardNumber = strings.ReplaceAll(cardNumber, " ", "")
	length := len(cardNumber)

	if length < 15 || length > 16 {
		return "", errors.New("unsupported credit card number format")
	}

	var groupings []int
	if length == 15 {
		groupings = []int{4, 6, 5} // Typical for American Express
	} else {
		groupings = []int{4, 4, 4, 4} // Default for standard cards
	}

	if cfg.Kind.MaskBankIdentifier {
		maskUntil := length - groupings[len(groupings)-1]
		masked := strings.Repeat(string([]rune{cfg.Symbol}), maskUntil) + cardNumber[maskUntil:]
		return formatCardNumber(masked, groupings), nil
	}

	visibleStart := groupings[0]
	visibleEnd := groupings[len(groupings)-1]
	if length <= visibleStart+visibleEnd {
		return cardNumber, nil
	}
	masked := cardNumber[:visibleStart] +
		strings.Repeat(string([]rune{cfg.Symbol}), length-visibleStart-visibleEnd) +
		cardNumber[length-visibleEnd:]
	return formatCardNumber(masked, groupings), nil
}

func init() {
	Register("credit_card", DefaultMasker(CreditCard))
}
