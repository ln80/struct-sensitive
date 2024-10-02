package sensitive_test

import (
	"log"
	"strings"

	sensitive "github.com/ln80/struct-sensitive"
)

// Example of a basic usage
func ExampleRedact() {
	type Profile struct {
		Email    string `sensitive:"data"`
		Fullname string `sensitive:"data"`
		Role     string
	}

	p := Profile{
		Email:    "eric.prosacco@example.com",
		Fullname: "Eric Prosacco",
		Role:     "Teacher",
	}

	err := sensitive.Redact(&p)
	if err != nil {
		log.Fatal(err)
	}

	print(p)

	// Output:
	// Profile{
	//   Email: "*************************",
	//   Fullname: "*************",
	//   Role: "Teacher",
	// }
}

// Example of a custom Redact function
func ExampleRedact_second() {
	type Profile struct {
		Email    string `sensitive:"data,kind=email"`
		Fullname string `sensitive:"data,kind=name"`
		Role     string
	}

	p := Profile{
		Email:    "eric.prosacco@example.com",
		Fullname: "Eric Prosacco",
		Role:     "Teacher",
	}

	err := sensitive.Redact(&p, func(rc *sensitive.RedactConfig) {
		rc.RedactFunc = func(fr sensitive.FieldReplace, val string) (string, error) {
			switch fr.Kind {
			case "email":
				return "ghost@unknown.net", nil
			case "name":
				return "Ghost", nil
			}
			return strings.Repeat("*", len(val)), nil
		}
	})
	if err != nil {
		log.Fatal(err)
	}

	print(p)

	// Output:
	// Profile{
	//   Email: "ghost@unknown.net",
	//   Fullname: "Ghost",
	//   Role: "Teacher",
	// }
}
