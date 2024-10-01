package sensitive

import (
	"reflect"
	"strings"
)

var (
	tagIDs       = []string{"sensitive", "pii", "sens"}
	tagSubjectID = "subjectID"
	tagData      = "data"
	tagDive      = "dive"
)

// TagOptions presents a map of options configured at `sensitive` tag.
type TagOptions map[string]string

type TagPayload struct {
	// ID is the tag ID ex `sensitive`, `pii`
	ID string
	// Name is the tag sensitive tag name ex `data`, `subjectID`
	Name string
	// Options presents the sensitive tag options
	Options TagOptions
}

// Marshal returns back the string representation of the parsed tag.
func (p TagPayload) Marshal() string {
	return marshalTag(p)
}

// ParseTag looks for a sensitive tag in the given field raw tag,
// parse it and returns a representational payload.
// It returns nil if the tag not found or misconfigured.
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
