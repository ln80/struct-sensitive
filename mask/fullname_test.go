package mask_test

import (
	"testing"

	"github.com/ln80/struct-sensitive/mask"
	"github.com/ln80/struct-sensitive/masktest"
)

func TestFullName(t *testing.T) {
	masktest.Run(t, mask.FullName, []masktest.Tc[mask.FullNameConfig]{
		{
			Value: "John Doe",
			Want:  "J*** D**",
			OK:    true,
		},
		{
			Value: "Emily Anne Doe",
			Want:  "E**** **** D**",
			OK:    true,
		},
		{
			Value: "X Æ A-12 Musk",
			Want:  "* * **** M***",
			OK:    true,
		},
		{
			// A one-letter word is masked whole: keeping its first letter
			// would keep all of it.
			Value: "A",
			Want:  "*",
			OK:    true,
		},
	})
}

func BenchmarkFullname(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := mask.FullName("Emily Anne Doe", func(mc *mask.Config[mask.FullNameConfig]) {
		}); err != nil {
			b.Fatal(err)
		}
	}
}
