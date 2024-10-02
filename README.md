

struct-sensitive
============

This Go library leverages struct tags to identify and manage sensitive fields in structs, ensuring data protection and compliance with privacy standards.

## Installation
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
    Device   Device `sensitive:"dive"`
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
For more usage and examples see the [Godoc](http://godoc.org/github.com/ln80/struct-sensitive).


## Features
- Supports multiple tag IDs: `sensitive`, `pii`, `sens`
- Provides functions for masking, redacting, and scanning sensitive data
- Includes a set of predefined masks
- Customizable behaviors through options and callbacks