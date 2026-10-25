package sensitive

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
)

var (
	tagIDs       = []string{"sensitive", "pii", "sens"}
	tagSubjectID = "subjectID"
	tagData      = "data"
	tagDive      = "dive"
)

// TagOptions is a map of options configured in the `sensitive` tag.
type TagOptions map[string]string

func (m TagOptions) Get(name string) string {
	opt, ok := m[name]
	if !ok {
		return ""
	}
	return opt
}

// TagPayload represents the metadata for a sensitive tag.
type TagPayload struct {
	// ID is the identifier of the tag, e.g., `sensitive`, `pii`.
	ID string

	// Name is the name of the sensitive tag, e.g., `data`, `subjectID`.
	Name string

	// Options represents the options associated with the sensitive tag.
	Options TagOptions
}

// Marshal returns back the string representation of the parsed tag.
func (p TagPayload) Marshal() string {
	return marshalTag(p)
}

func (p TagPayload) String() string {
	return p.Marshal()
}

// errBadTag marks a tag string that cannot be parsed.
// Scan and Check wrap it with ErrInvalidTagConfiguration.
var errBadTag = errors.New("invalid sensitive tag")

// ParseTag searches for a sensitive tag in the given field's raw tag,
// parses it, and returns a representational payload.
// It returns nil, nil when the field has no sensitive tag.
//
// Option values are split on the first '=' and may contain '='.
// A comma separates options and cannot appear inside a value.
// data accepts kind. subjectID accepts prefix. dive accepts no options.
// A field may carry only one of sensitive, pii, and sens.
func ParseTag(rt reflect.StructTag) (*TagPayload, error) {
	tag, tagID, err := extractTag(rt)
	if err != nil {
		return nil, err
	}
	if tag == "" {
		return nil, nil
	}
	name, opts, err := parseTag(tag)
	if err != nil {
		return nil, err
	}
	return &TagPayload{
		ID:      tagID,
		Name:    name,
		Options: opts,
	}, nil
}

// MustFieldTag extracts and parses the `sensitive` tag of the specified field in the given struct.
//
// It panics if the value is neither a struct nor a pointer to a struct, if the field is not found,
// or if the `sensitive` tag is misconfigured.
//
// Note: This function was primarily added to facilitate testing in downstream libraries.
func MustFieldTag(v any, field string) TagPayload {
	p, err := FieldTag(v, field)
	if err != nil {
		panic(err)
	}
	if p == nil {
		panic(errors.New("empty 'sensitive' tag config"))
	}
	return *p
}

// FieldTag extracts and parses the `sensitive` tag of the specified field in the given struct.
//
// It returns an error if the value is neither a struct nor a pointer to a struct,
// if the field is not found, or if the sensitive tag is misconfigured.
func FieldTag(v any, field string) (*TagPayload, error) {
	if v == nil {
		return nil, fmt.Errorf("%w '%v'", ErrUnsupportedType, nil)
	}
	rt := reflect.TypeOf(v)
	if rt.Kind() == reflect.Pointer {
		rt = rt.Elem()
	}

	if rt.Kind() != reflect.Struct {
		return nil, errors.New("unsupported type must be struct or struct pointer")
	}

	f, ok := rt.FieldByName(field)
	if !ok {
		return nil, fmt.Errorf("field '%s' not found in the struct", field)
	}

	return ParseTag(f.Tag)
}

func marshalTag(payload TagPayload) string {
	str := payload.ID + ":" + "\"" + payload.Name
	for k, v := range payload.Options {
		str += "," + k + "=" + v
	}
	str += "\""

	return str
}

func extractTag(rt reflect.StructTag) (tag, tagID string, err error) {
	for _, id := range tagIDs {
		v := rt.Get(id)
		if v == "" {
			continue
		}
		if tag != "" {
			return "", "", fmt.Errorf("%w: multiple tag IDs", errBadTag)
		}
		tag, tagID = v, id
	}
	return tag, tagID, nil
}

func allowedOption(name, key string) bool {
	switch name {
	case tagData:
		return key == "kind"
	case tagSubjectID:
		return key == "prefix"
	default:
		return false
	}
}

func parseTag(tagStr string) (name string, opts TagOptions, err error) {
	parts := strings.Split(tagStr, ",")
	name = strings.TrimSpace(parts[0])
	opts = make(TagOptions)
	for _, opt := range parts[1:] {
		key, val, ok := strings.Cut(opt, "=")
		if !ok {
			return "", nil, fmt.Errorf("%w: option %q", errBadTag, strings.TrimSpace(opt))
		}
		key = strings.TrimSpace(key)
		val = strings.TrimSpace(val)
		if !allowedOption(name, key) {
			return "", nil, fmt.Errorf("%w: option %q", errBadTag, key)
		}
		opts[key] = val
	}
	return name, opts, nil
}
