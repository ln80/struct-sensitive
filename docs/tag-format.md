# Tag format

This document is normative: `ParseTag` and `Scan` implement it, and a
mismatch is a bug. From v1.0 a tag that is valid stays valid with the same
meaning ([api-stability.md](api-stability.md)).

## 1. Syntax

```
tag     = id ':"' name { "," option } '"'
id      = "sensitive" | "pii" | "sens"
name    = "data" | "dive" | "subjectID"
option  = key "=" value
```

- The three IDs are equivalent. A field carries at most one of them.
- Spaces around the name, keys and values are trimmed.
- A value is split on the first `=`, so it may contain `=`. It cannot contain
  a comma.
- IDs, names and keys are case-sensitive, as Go struct tags are.

## 2. Names and options

| Name | Meaning | Options |
|---|---|---|
| `subjectID` | The field holds the subject the struct's data belongs to | `prefix`: prepended to the field's value |
| `data` | The field holds sensitive data | `kind`: selects a mask (`email`, `ipv4_addr`, `credit_card`, `fullname`, or a registered one). `replace`: the value a caller writes once the data can no longer be read, such as privacy-engine for a forgotten subject |
| `dive` | The field holds structs to scan | none |

## 3. Field types

| Name | Accepted types |
|---|---|
| `subjectID` | `string` kinds, `[]byte` kinds, or one pointer to either |
| `data` | `string` kinds and `[]byte` kinds, one pointer to either, and slices of those or of pointers to those |
| `dive` | a struct, a pointer to one, or a slice or map of structs or of pointers to structs |

Named types count by their kind. Integers, `[]rune` and other types Go can
convert to a string are refused: they do not round-trip.

## 4. Errors

Each of the following fails, from `ParseTag` or at `Scan`, `Check`,
`Redact` and `Mask`. Nothing is skipped silently.

- an empty tag, two IDs on one field, an unknown name;
- an unknown option for the name, a repeated option, an option without `=`;
- a field type outside section 3;
- a tag on an unexported field.

Unknown options already fail, so a later release can add an option without
changing what valid tags mean.

## 5. Subjects

The subject of a data field is the nearest `subjectID`: its own struct's,
else its parent's. `Scan` with `SingleSubject` refuses a value whose data
uses more than one subject. A subject with an empty value is no subject;
`WithRequireSubject` then fails with `ErrSubjectIDNotFound`.
