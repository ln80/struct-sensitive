package sensitive_test

import (
	"log"
	"strings"

	sensitive "github.com/ln80/struct-sensitive"
)

func Example_redact_simple() {
	type Profile struct {
		Email string `sensitive:"data"`
	}

	p := Profile{
		Email: "eric.prosacco@example.com",
	}

	err := sensitive.Redact(&p)
	if err != nil {
		log.Fatal(err)
	}

	print(p)

	// Output:
	// Profile{
	//   Email: "*************************",
	// }

}

func Example_redact_custom() {
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
				return "****@****.***", nil
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
	//   Email: "****@****.***",
	//   Fullname: "Ghost",
	//   Role: "Teacher",
	// }
}
