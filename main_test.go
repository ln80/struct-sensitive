package sensitive

func ptr[T any](t T) *T {
	return &t
}

type Email string

type Profile struct {
	ID       string   `sensitive:"subjectID"`
	Email    Email    `sensitive:"data,kind=email"`
	Phone    *string  `sensitive:"data"`
	Fullname string   `sensitive:"data"`
	Devices  []Device `sensitive:"dive"`
}

type Address struct {
	Street string `sensitive:"data"`
}
type Device struct {
	IPAddr string `sensitive:"data,kind=ipv4_addr"`
}

type InvalidSubject struct {
	Subject  string `sensitive:"subjectID"`
	Subject2 string `sensitive:"subjectID"`
}

type InvalidTag struct {
	Data string `sensitive:"invalid"`
}
