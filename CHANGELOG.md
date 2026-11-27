# Changelog

All notable changes. The API follows [semantic versioning](https://semver.org);
see [docs/api-stability.md](docs/api-stability.md).

## v0.9.1

### Changed

- Go 1.26 or later; CI tests on Go 1.26 and 1.27. Go 1.25 is out of support.

## v0.9.0

The API freeze before v1. Breaking.

### Changed

- `Scan(v, requireSubject, opts...)` is `Scan(v, opts...)`; use
  `WithRequireSubject()`.
- Options are opaque: `ScanOption`, `RedactOption` and `MaskedCopyOption`
  replace `func(*ScanConfig)`, `func(*RedactConfig)` and
  `func(*MaskedCopyConfig)`. Use `WithRedactFunc(fn)` instead of setting
  `RedactFunc`, `WithRegisteredMasks()` (now a function call), and
  `WithoutDeepCopy()` instead of `DeepCopy: false`.
- `Redact` no longer takes a subject requirement.
- `MaskedCopy`, which panics, is `MustMaskedCopy`.
- `Struct.SubjectID()` returns `(id, ok)` instead of panicking.
- `mask.Register`, `Override` and `Of` use the exported `mask.Func`.
- `ParseTag` refuses an unknown name, a repeated option and an empty tag.
- `TagPayload.Marshal` sorts options.
- The `fullname` mask masks a one-letter word whole.
- Go 1.25 or later. License: Apache 2.0 (was MIT).

### Removed

- `ErrRedactFuncNotFound`: a nil redact function keeps the default.

### Fixed

- A `subjectID` with a `prefix` and an empty value resolved to the prefix,
  so records without an ID shared one subject.
- The `email` mask returned `@domain` unchanged for an empty local part.

### Added

- `docs/tag-format.md` (normative), `docs/api-stability.md`, `SECURITY.md`.
- Fuzz targets `FuzzParseTag`, `FuzzMask`, `FuzzScanSubjects`, run twice a
  week in CI.
- CI: actions pinned by SHA, read-only permissions, govulncheck, gosec,
  Dependabot, a 90% coverage gate.

## v0.8.0

Fail closed: tagged fields that would be skipped or leaked are errors, and
subject IDs no longer collapse to one placeholder. `Plan` and `Commit`,
`FieldReplace.Path`. Subject modes
(`WithSubjectMode`, `SingleSubject`), `Struct.Subjects`, and the `replace`
option on data tags.

## v0.7.0

Struct scanning improvements and string slice data fields.
