package mask_test

import (
	"testing"

	"github.com/ln80/struct-sensitive/mask"
	"github.com/ln80/struct-sensitive/masktest"
)

func TestIPv4Addr(t *testing.T) {
	masktest.Run(t, mask.IPv4Addr, []masktest.Tc[mask.IPv4AddrConfig]{
		{
			Value: "2001:0000:130F:0000:0000:09C0:876A:130B",
			OK:    false,
		},
		{
			Value: "169.251.10",
			OK:    false,
		},
		{
			Value: "169.251.207.194",
			Want:  "169.251.207.***",
			OK:    true,
			Err:   nil,
		},
		{
			Option: func(mc *mask.Config[mask.IPv4AddrConfig]) {
				mc.Kind.OctetsToMask = 2
			},
			Value: "169.251.207.194",
			Want:  "169.251.***.***",
			OK:    true,
		},
		{
			Option: func(mc *mask.Config[mask.IPv4AddrConfig]) {
				mc.Symbol = '0'
				mc.Kind.OctetsToMask = 1
				mc.Kind.OneOctetSymbol = true
			},
			Value: "169.251.207.194",
			Want:  "169.251.207.0",
			OK:    true,
		},
	})
}

func BenchmarkIPv4Addr(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := mask.IPv4Addr("169.251.207.194", func(mc *mask.Config[mask.IPv4AddrConfig]) {
			mc.Kind.OctetsToMask = 2
		}); err != nil {
			b.Fatal(err)
		}
	}
}
