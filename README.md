

## struct-sensitive

This Go library leverages struct tags to identify and manage sensitive fields in structs, ensuring data protection and compliance with privacy standards.

## Installation
You can install the library using Go modules:
```bash
go get github.com/ln80/struct-sensitive
```

## Basic usage

Here's a basic example of how to use the library:

```go
type Device struct {
	IP string `pii:"data,kind=ipv4_addr"`
}

type Profile struct {
    Email    string `sensitive:"data,kind=email"`
    Fullname string `sensitive:"data"`
    Device   Device `pii:"dive"`
}

var profile = Profile{
	Email:    "eric.prosacco@example.com",
	Fullname: "Eric Prosacco",
	Device: Device{
		IP: "28.175.98.7",
	},
}

_ = sensitive.Mask(&profile)

// Output:
// Profile{
//   Email: "*************@example.com",
//   Fullname: "*************",
//   Device: Device{
//    IP: "28.175.98.***",
//   },
// }
```

## Features
- Supports multiple tag IDs: `sensitive`, `pii`, `sens`
- Provides functions for masking, redacting, and scanning sensitive data
- Customizable through options and callbacks