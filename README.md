


struct-sensitive
============
[![Coverage Status](https://coveralls.io/repos/github/ln80/struct-sensitive/badge.svg?branch=main)](https://coveralls.io/github/ln80/struct-sensitive?branch=main)
[![GoDoc](https://godoc.org/github.com/ln80/struct-sensitive?status.svg)](https://godoc.org/github.com/ln80/struct-sensitive)

This Go library leverages struct tags to identify and manage sensitive fields in structs, ensuring data protection and compliance with privacy standards.

In simple terms, it provides Redact and Mask utilities for handling fields that contain sensitive data such as PII, PHI, PCI, SSN.

## Installation
```bash
go get github.com/ln80/struct-sensitive
```
```go
import (
    sensitive "github.com/ln80/struct-sensitive"
)
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

if err := sensitive.Mask(&profile); err != nil {
    // The struct is fully redacted. err names the field path, not the value.
}

// Output:
// Profile{
//   Email: "*************@example.com",
//   Fullname: "*************",
//   Device: Device{
//    IP: "28.175.98.***",
//   },
// }
```

### Tags basic usage:

- `sensitive:data` indicates that the field contains sensitive data and may also specify its kind (optional).

- `sensitive:dive` specifies that the nested struct or the collection of structs contains sensitive fields.

- `sensitive:subjectID` marks the field value as the subject identifier to whom the sensitive data belongs. Only one subject ID value is authorized at the struct level when required.

Example of registering a default mask for a particular sensitive data kind (e.g., 'be_nrn'):

```go
import (
    "github.com/ln80/struct-sensitive/mask"
)

...

defaultMask := func(val string) (masked string, err error) {
    // TODO implement 'be_nrn' mask behavior here
    masked = "**.**.**-***-**"
    return
}

if err := mask.Register("be_nrn", defaultMask); err != nil {
    // Register rejects a nil function, an empty kind, and a kind that already exists.
    // Use mask.Override to replace a mask on purpose.
}
```

For more usage and examples see the [Godoc](http://godoc.org/github.com/ln80/struct-sensitive).


## Features
- Provides functions for masking, redacting, and scanning sensitive data
- Includes a set of predefined masks
- Customizable behaviors through options and callbacks
- Supports multiple tag IDs: `sensitive`, `pii`, `sens` that can be used interchangeably.

### Predefined masks:
- `email` keeps the domain, which can reveal an organization
- `ipv4_addr` masks one octet by default and leaves the network prefix visible
- `credit_card` keeps the BIN and the last 4 digits, the PCI display limit
- `fullname` keeps initials and word lengths

These shapes are intentional. Use full redaction when the leftover structure is still identifying. `mask.Register` adds a kind and refuses to replace one; `mask.Override` replaces it.

## Limitations
1.  Only fields of types convertible to `string` or `*string` are supported, although nesting structs directly or through collections (slices and maps) is also supported. String slices (`[]string`, `[]*string`) are supported as data fields.

2. Self-referencing types are supported. A value that contains a pointer cycle returns an error. A chain of more than 10000 structs returns an error.

