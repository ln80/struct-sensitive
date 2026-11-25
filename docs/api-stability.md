# API stability

The Go API follows [semantic versioning](https://semver.org). Before v1.0,
minor releases may break it; from v1.0, only a major release does.

## What the promise covers

- Every exported identifier of `sensitive`, `mask` and `masktest`. Not
  `internal/`, error message text, or the output of the predefined masks
  beyond their documented shape.
- The tag format ([tag-format.md](tag-format.md)): a valid tag stays valid
  with the same meaning.

## Rules

1. **Options are opaque.** `ScanOption`, `RedactOption` and
   `MaskedCopyOption` are built by their `With*` functions. New options may
   be added.
2. **Interfaces returned by the library may gain methods.** `Struct` and
   `Replacement` have an unexported method: only this package implements
   them.
3. **Structs may gain fields.** `FieldReplace`, `TagPayload` and the mask
   configs may grow. Use field names in composite literals.
4. **Errors are matched with `errors.Is`**, never by message.
5. **The tag format only grows.** A new option or name may be added; an
   existing one keeps its meaning. Tags that fail today may become valid,
   never the reverse.
