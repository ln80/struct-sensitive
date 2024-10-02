package sensitive_test

import (
	"errors"
	"log"
	"regexp"

	sensitive "github.com/ln80/struct-sensitive"
	"github.com/ln80/struct-sensitive/internal/option"
	"github.com/ln80/struct-sensitive/mask"
)

// Example of masking with a custom registered mask (ex: Belgian National Register Number)
func ExampleMask() {

	type Profile struct {
		Email    string `sensitive:"data,kind=email"`
		NRN      string `sensitive:"data,kind=be_nrn"`
		Fullname string `sensitive:"data"`
	}

	// Define the Belgian National Register Number (be_nrn) mask behavior.
	//
	// Assuming, based on business requirements, revealing the birth date is acceptable by default.
	//
	// You can evolve the mask behavior by adding options to the struct.
	// However, note that only the default options are used by the [sensitive.Mask] function.
	// Alternatively, you can define and apply the mask directly in your code if you need custom behavior for specific cases.
	type BeNRNConfig struct {
		RevealBirthDate bool
	}

	BeNRNRegex := regexp.MustCompile(`^(\d{2})\.(\d{2})\.(\d{2})-(\d{3})-(\d{2})$`)

	BeNRNMask := func(val string, opts ...func(*mask.Config[BeNRNConfig])) (masked string, err error) {
		cfg := mask.DefaultConfig(BeNRNConfig{
			RevealBirthDate: true,
		})
		option.Apply(&cfg, opts)

		matches := BeNRNRegex.FindStringSubmatch(val)
		if matches == nil {
			return "", errors.New("invalid BE_NRN format")
		}

		if !cfg.Kind.RevealBirthDate {
			masked = "**.**.**-***-**"
			return
		}
		masked = matches[1] + "." + matches[2] + "." + matches[3] + "-***-**"
		return
	}

	mask.Register("be_nrn", mask.DefaultMasker(BeNRNMask))

	p := Profile{
		Email:    "eric.prosacco@example.com",
		NRN:      "85.12.25-123-45",
		Fullname: "Eric Prosacco",
	}

	err := sensitive.Mask(&p)
	if err != nil {
		log.Fatal(err)
	}

	print(p)

	// Output:
	// Profile{
	//   Email: "*************@example.com",
	//   NRN: "85.12.25-***-**",
	//   Fullname: "*************",
	// }
}
