package mask_test

import (
	"testing"

	"github.com/ln80/struct-sensitive/mask"
	"github.com/ln80/struct-sensitive/masktest"
)

func TestEmail(t *testing.T) {
	masktest.Run(t, mask.Email, []masktest.Tc[mask.EmailConfig]{
		{
			Value: "invalid_example.com",
			OK:    false,
		},
		{
			Value: "email.bar@example.com",
			Want:  "*********@example.com",
			OK:    true,
		},
		{
			Option: func(mc *mask.Config[mask.EmailConfig]) {
				mc.Kind.MaskDomain = true
			},
			Value: "email@example.com",
			Want:  "*****@*******.***",
			OK:    true,
		},
		{
			Option: func(mc *mask.Config[mask.EmailConfig]) {
				mc.Symbol = '□'
				mc.Kind.MaskDomain = true
			},
			Value: "email@example.com",
			Want:  "□□□□□@□□□□□□□.□□□",
			OK:    true,
		},
	})
}

func BenchmarkEmail(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := mask.Email("Kenna31@gmail.com", func(mc *mask.Config[mask.EmailConfig]) {
			mc.Kind.MaskDomain = true
		}); err != nil {
			b.Fatal(err)
		}
	}
}
