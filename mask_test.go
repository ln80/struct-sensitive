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

func TestMaskedCopy(t *testing.T) {
	profile := Profile{
		Email:    "email@example.com",
		Fullname: "Guadalupe Kemmer DDS",
	}

	cp, err := NewMaskedCopy(profile)
	if err != nil {
		t.Fatal("expect err be nil, got", err)
	}

	maskedCopy := cp.Value()

	if reflect.DeepEqual(profile, maskedCopy) {
		t.Fatalf("expect not be equals %v, %v", profile, maskedCopy)
	}

	if err := Mask(&profile); err != nil {
		t.Fatal("expect err be nil, got", err)
	}

	if !reflect.DeepEqual(profile, maskedCopy) {
		t.Fatalf("expect be equals %v, %v", profile, maskedCopy)
	}
}

func TestMaskedCopy_PointerFields(t *testing.T) {
	original := Profile{
		ID:       "usr-1",
		Email:    "email@example.com",
		Fullname: "Guadalupe Kemmer DDS",
		Phone:    ptr("519-491-6780"),
		Devices: []Device{
			{IPAddr: "169.251.207.194"},
		},
	}

	cp, err := NewMaskedCopy(original)
	if err != nil {
		t.Fatal("expect err be nil, got", err)
	}

	revealed := cp.Reveal()

	if revealed.Email != "email@example.com" {
		t.Fatalf("Reveal().Email: want original, got %q", revealed.Email)
	}
	if revealed.Fullname != "Guadalupe Kemmer DDS" {
		t.Fatalf("Reveal().Fullname: want original, got %q", revealed.Fullname)
	}
	if *revealed.Phone != "519-491-6780" {
		t.Fatalf("Reveal().Phone: want original, got %q", *revealed.Phone)
	}
	if revealed.Devices[0].IPAddr != "169.251.207.194" {
		t.Fatalf("Reveal().Devices[0].IPAddr: want original, got %q", revealed.Devices[0].IPAddr)
	}

	masked := cp.Value()
	if masked.Email == "email@example.com" {
		t.Fatal("Value().Email should be masked")
	}
	if *masked.Phone == "519-491-6780" {
		t.Fatal("Value().Phone should be masked")
	}
}
