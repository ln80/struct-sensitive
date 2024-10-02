

struct-sensitive
============

This Go library leverages struct tags to identify and manage sensitive fields in structs, ensuring data protection and compliance with privacy standards.

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

var defaultMask := func(val string) (masked string, err error) {
    // TODO implement 'be_nrn' mask behavior here
    masked = "**.**.**-***-**"
    return
}

mask.Register("be_nrn", defaultMask)
```

For more usage and examples see the [Godoc](http://godoc.org/github.com/ln80/struct-sensitive).


## Features
- Provides functions for masking, redacting, and scanning sensitive data
- Includes a set of predefined masks
- Customizable behaviors through options and callbacks
- Supports multiple tag IDs: `sensitive`, `pii`, `sens` that can be used interchangeably.

### Predefined masks:
- `email`
- `ipv4_addr`

## Limitations
1.  Only fields of types convertible to `string` or `*string` are supported, although nesting structs directly or through collections (slices and maps) is also supported.

2. Self-Referencing Types are supported, allowing types to include fields of the same type. However, Self-Referencing Values (instances that create a reference loop) are not supported.

3. At the moment, collections of types convertible to `string` or `*string` are not supported.

