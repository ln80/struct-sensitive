package sensitive

import (
	"errors"
	"reflect"
	"strconv"
	"testing"
)

func TestMask(t *testing.T) {
	type tc struct {
		val  any
		want any
		ok   bool
		err  error
	}
	tcs := []tc{
		{
			val:  nil,
			want: nil,
			ok:   false,
			err:  ErrUnsupportedType,
		},
		{
			val: &Profile{
				Email:    "invalid_email.com",
				Fullname: "Guadalupe Kemmer DDS",
				Devices: []Device{
					{
						IPAddr: "169.251.207.194",
					},
					{
						IPAddr: "c64d:8716:fc03:5fed:4b91:e954:a083:9bad",
					},
				},
			},
			// Mask fails if the predefined mask is incompatible with the sensitive value
			ok: false,
		},
		{
			val: &Profile{
				Email:    "email@example.com",
				Fullname: "Guadalupe Kemmer DDS",
				Devices: []Device{
					{
						IPAddr: "169.251.207.194",
					},
				},
			},
			want: &Profile{
				Email:    "*****@example.com",
				Fullname: "********************",
				Devices: []Device{
					{
						IPAddr: "169.251.207.***",
					},
				},
			},
			ok: true,
		},
		func() tc {
			// case of a sensitive data kind without a registered default mask.
			// In this case the default redact func is used.
			type Profile2 struct {
				Profile         `sensitive:"dive"`
				InsuranceNumber string `sensitive:"data,kind=test_insurance_number"`
			}
			return tc{
				val: &Profile2{
					Profile: Profile{
						Email:    "email@example.com",
						Fullname: "Guadalupe Kemmer DDS",
					},
					InsuranceNumber: "TN 31 12 58 F",
				},
				want: &Profile2{
					Profile: Profile{
						Email:    "*****@example.com",
						Fullname: "********************",
					},
					InsuranceNumber: "*************",
				},
				ok: true,
			}
		}(),
	}

	for i, tc := range tcs {
		t.Run("tc: "+strconv.Itoa(i), func(t *testing.T) {
			err := Mask(tc.val)
			if !tc.ok {
				if err == nil {
					t.Fatal("expect err not to be nil")
				}
				if tc.err != nil && !errors.Is(err, tc.err) {
					t.Fatalf("expect err is %v, got %v", tc.err, err)
				}
				return
			}
			if err != nil {
				t.Fatal("expect err be nil, got", err)
			}
			if !reflect.DeepEqual(tc.want, tc.val) {
				t.Fatalf("want %s, got %s", tc.want, tc.val)
			}
		})
	}
}
