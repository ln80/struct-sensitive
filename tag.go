package sensitive

import (
	"reflect"
	"strings"
)

var (
	tagIDs       = []string{"sens", "sensitive"}
	tagSubjectID = "subjectID"
	tagData      = "data"
	tagDive      = "dive"
)

func extractTag(rt reflect.StructTag) (tag string) {
	for _, id := range tagIDs {
		tag = rt.Get(id)
		if tag != "" {
			return
		}
	}
	return
}

func parseTag(tagStr string) (name string, opts map[string]string) {
	if tagStr == "" {
		return
	}

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
