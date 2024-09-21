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

func extractTag(rt reflect.StructTag) (tag string) {
	for _, id := range tagIDs {
		tag = rt.Get(id)
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
