package mask_test

import (
	"testing"

	"github.com/ln80/struct-sensitive/mask"
	"github.com/ln80/struct-sensitive/masktest"
)

func TestCreditCard(t *testing.T) {
	masktest.Run(t, mask.CreditCard, []masktest.Tc[mask.CreditCardConfig]{
		{
			Value: "3012",
			OK:    false,
		},
		{
			Value: "4111 3145 4001 1111",
			Want:  "4111 **** **** 1111",
			OK:    true,
		},
		{
			Value: "4111 3145 4001 1111",
			Want:  "**** **** **** 1111",
			OK:    true,
			Option: func(c *mask.Config[mask.CreditCardConfig]) {
				c.Kind.MaskBankIdentifier = true
			},
		},
		{
			Value: "3714 496353 98431",
			Want:  "3714 ****** 98431",
			OK:    true,
		},
		{
			Value: "371449635398431",
			Want:  "3714 ****** 98431",
			OK:    true,
		},
		{
			Value: "3714 496353 98431",
			Want:  "**** ****** 98431",
			OK:    true,
			Option: func(c *mask.Config[mask.CreditCardConfig]) {
				c.Kind.MaskBankIdentifier = true
			},
		},
		{
			Value: "3714 496353 98431",
			Want:  "$$$$ $$$$$$ 98431",
			OK:    true,
			Option: func(c *mask.Config[mask.CreditCardConfig]) {
				c.Kind.MaskBankIdentifier = true
				c.Symbol = '$'
			},
		},
	})
}

func BenchmarkCreditCard(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := mask.CreditCard("4111 3145 4001 1111", func(mc *mask.Config[mask.CreditCardConfig]) {
			mc.Kind.MaskBankIdentifier = true
		}); err != nil {
			b.Fatal(err)
		}
	}
}
