/*
Package sensitive provides a set functions to handle sensitive fields in structs, including:

  - [Mask] partially redacts sensitive data while preserving the format of the data type (aka kind).
    It uses a set of predefined masks (e.g 'email' 'ipv4_addr') and allows to register additional masks.

  - [Redact] replaces sensitive field values with a redaction symbol ('*') by default.
    The behavior can be customized through optional parameters.

  - [Scan] is a lower-level function that gives access to sensitive struct metadata and a fields replacer.
    This can be used to implement more advanced features such as client-side encryption.

  - [Check] determines whether a struct contains any sensitive data fields.

Package sensitive leverages Go struct tags to identify and categorize struct sensitive field.
It supports the following tag IDs `sensitive`, `pii`, `sens`.
Here's an example:

	type Profile struct {
		Email    string `sensitive:"data,kind=email"`
		Fullname string `sensitive:"data,kind=name"`
		Role     string
	}

Applying the default masking logic:

	var profile := Profile{
		Email:    "eric.prosacco@example.com",
		Fullname: "Eric Prosacco",
		Role:     "Teacher",
	}

	_ = sensitive.Mask(&profile)

	// After masking:
	//
	// Profile{
	//   Email: "****.********@example.com",
	//   Fullname: "*************",
	//   Role: "Teacher",
	// }

	// Notes:
	// - The default behavior of the `email` mask is to hide the local part while revealing the domain part.
	// - The library does not provide a default mask for `name`; therefore, the default redaction behavior is applied.
	// - You may consider defining a specific `name` mask and registering it using [mask.Register].
	// - The Role field is not tagged as sensitive, so it remains unchanged.

Applying a custom redact logic:

	type Profile struct {
		Email    string `sensitive:"data,kind=email"`
		Fullname string `sensitive:"data,kind=name"`
		Role     string
	}

	var profile := Profile{
		Email:    "eric.prosacco@example.com",
		Fullname: "Eric Prosacco",
		Role:     "Teacher",
	}

	option := func(rc *sensitive.RedactConfig) {
		rc.RedactFunc = func(fr sensitive.FieldReplace, val string) (string, error) {
			switch fr.Kind {
			case "email":
				return "ghost@unknown.net", nil
			case "name":
				return "Ghost", nil
			}
			return strings.Repeat("*", len(val)), nil
		}
	}

	_ = sensitive.Redact(&profile, option)

	// After redacting:
	//
	// Profile{
	//   Email: "ghost@unknown.net",
	//   Fullname: "Ghost",
	//   Role: "Teacher",
	// }
*/
package sensitive
