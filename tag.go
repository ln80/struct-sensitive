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

// TagOptions presents a map of options configured at the `sensitive` tag.
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

// ParseTag searches for a sensitive tag in the given field's raw tag,
// parses it, and returns a representational payload.
// It returns nil if the tag is not found or is misconfigured.
func ParseTag(rt reflect.StructTag) *TagPayload {
	tag, tagID := extractTag(rt)
	if tag == "" {
		return nil
	}
	name, opts := parseTag(tag)
	return &TagPayload{
		ID:      tagID,
		Name:    name,
		Options: opts,
	}
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
// or if the field is not found. It returns an empty value if the `sensitive` tag is misconfigured.
func FieldTag(v any, field string) (*TagPayload, error) {
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

	return ParseTag(f.Tag), nil
}

func marshalTag(payload TagPayload) string {
	str := payload.ID + ":" + "\"" + payload.Name
	for k, v := range payload.Options {
		str += "," + k + "=" + v
	}
	str += "\""

	return str
}

func extractTag(rt reflect.StructTag) (tag, tagID string) {
	for _, id := range tagIDs {
		tag, tagID = rt.Get(id), id
		if tag != "" {
			return
		}
	}
	return
}

func parseTag(tagStr string) (name string, opts TagOptions) {
	parts := strings.Split(tagStr, ",")
	name = strings.TrimSpace(parts[0])
	opts = make(map[string]string)
	for _, opt := range parts[1:] {
		splits := strings.Split(opt, "=")
		if len(splits) == 2 {
			name, val := strings.TrimSpace(splits[0]), strings.TrimSpace(splits[1])
			opts[name] = val
		}
	}
	return
}
