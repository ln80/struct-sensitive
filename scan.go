package sensitive

import (
	"errors"
	"fmt"
	"reflect"
	"sync"
)

var (
	ErrInvalidTagConfiguration = errors.New("invalid 'sensitive' tag configuration")
	ErrUnsupportedType         = errors.New("unsupported 'sensitive' type")
	ErrUnsupportedFieldType    = errors.New("'sensitive' field type must be convertible to string")
	ErrMultipleNestedSubjectID = errors.New("potential multiple nested subject IDs")
	ErrSubjectIDNotFound       = errors.New("subject ID is not found")
)

// Struct presents an accessor to sensitive struct fields and subject.
type Struct interface {
	// Replace accepts a replace function and calls it on each sensitive data field
	Replace(fn ReplaceFunc) error
	// SubjectID returns the resolved subjectID of the sensitive struct.
	// It panics if the subjectID is not resolved.
	SubjectID() string
	// HasSensitive tells wether or not the struct has sensitive data fields.
	HasSensitive() bool

	private()
}

// FieldReplace contains sensitive field metadata.
type FieldReplace struct {
	// SubjectID is the subjectID resolved at the struct-level.
	// This field might be empty if it's not required by the upstream caller.
	SubjectID string
	// Name is the name of the sensitive field.
	Name string
	// RType is the original type of the sensitive field.
	// Note that the type must be convertible to [string].
	RType reflect.Type
	// Kind is the user-defined type of sensitive data defined as 'sensitive' tag option.
	Kind string

	// Options are `sensitive` tag options
	Options TagOptions
}

// ReplaceFunc is a callback function executed by [Struct.Replace] Method.
// It does receive the sensitive field original value converted to string and returns the new value.
type ReplaceFunc func(fr FieldReplace, val string) (string, error)

// Scan scans the given value and returns a sensitive struct accessor.
// It fails if the value is not a struct pointer or 'sensitive' tag is misconfigured.
//
// [Struct] accessor and [Scan] function are low-level components
// In most cases you may consider using [Redact] and [Mask].
func Scan(v any, requireSubject bool) (accessor Struct, err error) {
	defer func() {
		// normalize error
		if err != nil && !errors.Is(err, ErrUnsupportedType) {
			err = errors.Join(ErrInvalidTagConfiguration, err)
		}
	}()

	if v == nil {
		err = fmt.Errorf("%w '%v'", ErrUnsupportedType, nil)
		return
	}

	tt := reflect.TypeOf(v)
	if tt.Kind() != reflect.Pointer {
		err = fmt.Errorf("%w '%v'", ErrUnsupportedType, tt)
		return
	}
	if tt.Kind() == reflect.Pointer {
		tt = tt.Elem()
	}
	if tt.Kind() != reflect.Struct {
		err = fmt.Errorf("%w '%v'", ErrUnsupportedType, tt)
		return
	}

	var ssType sensitiveStructType
	ssType, err = scanStructType(tt)
	if err != nil {
		return
	}
	if !ssType.hasSensitive {
		// As struct doesn't have sensitive data, no need to proceed and resolve subject ID value.
		// Therefore getting calling 'reflect.ValueOf', considering its cost, doesn't make sense.
		accessor = sensitiveStruct{
			typ: ssType,
		}
		return
	}

	structValue := sensitiveStruct{
		typ: ssType,
		val: reflect.ValueOf(v).Elem(),
	}

	if requireSubject {
		if _, err = structValue.resolveSubject(); err != nil {
			return
		}
	}

	accessor = structValue
	return
}

var (
	stringType = reflect.TypeFor[string]()
)

var (
	cache   map[reflect.Type]*sensitiveStructType = make(map[reflect.Type]*sensitiveStructType)
	cacheMu sync.RWMutex
)

type sensitiveStructContext struct {
	seen map[reflect.Type]*sensitiveStructType
}

type sensitiveField struct {
	sf                      reflect.StructField
	isSub, isData, isNested bool
	prefix                  string
	isSlice, isMap          bool
	nestedStructType        *sensitiveStructType
	nestedStructTypeRef     reflect.Type
	kind                    string
	options                 TagOptions
}

func (f sensitiveField) getType(cache map[reflect.Type]*sensitiveStructType) *sensitiveStructType {
	if f.nestedStructTypeRef != nil {
		return cache[f.nestedStructTypeRef]
	}
	return f.nestedStructType
}

func (f sensitiveField) IsZero() bool {
	// TBD find a better condition??
	return f.sf.Name == ""
}

type sensitiveStructType struct {
	hasSensitive    bool
	subField        sensitiveField
	sensitiveFields []sensitiveField
	rt              reflect.Type
}

type sensitiveStruct struct {
	typ       sensitiveStructType
	val       reflect.Value
	subjectID string
}

func (ps sensitiveStruct) private() {}

var _ Struct = &sensitiveStruct{}

// resolveSubject resolves the sensitive struct subject ID value by walking through
// the struct and its nested sensitive structs.
//
// It returns an error if the subject ID is missing or duplicated.
func resolveSubject(pt sensitiveStructType, pv reflect.Value) (string, error) {
	subject := ""
	if !pt.subField.IsZero() {
		subject = pt.subField.prefix + reflect.Indirect(pv.FieldByIndex(pt.subField.sf.Index)).String()
	}

	for _, ssField := range pt.sensitiveFields {
		if !ssField.isNested {
			continue
		}

		sensitiveFieldV := pv.FieldByIndex(ssField.sf.Index)
		if sensitiveFieldV.IsZero() {
			continue
		}

		cacheMu.Lock()
		ssT := ssField.getType(cache)
		cacheMu.Unlock()
		// I believe ssT can't be nil
		ssTv := *ssT
		sensitiveFieldV = reflect.Indirect(sensitiveFieldV)
		nestedSubject := ""
		switch {
		case ssField.isSlice:
			for i := 0; i < sensitiveFieldV.Len(); i++ {
				nestedSubject, _ = resolveSubject(ssTv, sensitiveFieldV.Index(i))
				if nestedSubject != "" {
					break
				}
			}
		case ssField.isMap:
			for _, k := range sensitiveFieldV.MapKeys() {
				nestedSubject, _ = resolveSubject(ssTv, sensitiveFieldV.MapIndex(k))
				if nestedSubject != "" {
					break
				}
			}
		default:
			nestedSubject, _ = resolveSubject(ssTv, sensitiveFieldV)
		}

		if nestedSubject != "" {
			if subject != "" && subject != nestedSubject {
				return "", ErrMultipleNestedSubjectID
			}
			subject = nestedSubject
		}
	}

	if subject == "" {
		return "", fmt.Errorf("%w in '%v'", ErrSubjectIDNotFound, pt.rt)
	}
	return subject, nil
}

func (ps *sensitiveStruct) resolveSubject() (string, error) {
	if ps.subjectID == "" {
		var err error
		ps.subjectID, err = resolveSubject(ps.typ, ps.val)
		if err != nil {
			return "", err
		}
	}
	return ps.subjectID, nil
}

func (ss sensitiveStruct) SubjectID() string {
	s, err := ss.resolveSubject()
	if err != nil {
		panic(err)
	}
	return s
}

func (ss sensitiveStruct) HasSensitive() bool {
	return ss.typ.hasSensitive
}

func (s sensitiveStruct) Replace(fn ReplaceFunc) error {
	var (
		newVal string
		err    error
	)
	for _, ssField := range s.typ.sensitiveFields {
		v := s.val.FieldByIndex(ssField.sf.Index)

		if v.IsZero() {
			continue
		}

		if !v.CanSet() {
			continue
		}
		elem := reflect.Indirect(v)

		if ssField.isData {
			val := elem.String()

			newVal, err = fn(FieldReplace{
				SubjectID: s.subjectID,
				RType:     ssField.sf.Type,
				Kind:      ssField.kind,
				Options:   ssField.options,
			}, val)
			if err != nil {
				return err
			}
			if newVal != val {
				elem.SetString(newVal)
			}
			continue
		}

		if ssField.isNested {
			var ssT sensitiveStructType

			cacheMu.Lock()
			ssTPtr := ssField.getType(cache)
			cacheMu.Unlock()

			// I believe ssTPtr can't be nil
			ssT = *ssTPtr
			if !ssT.hasSensitive {
				continue
			}

			switch {
			case ssField.isSlice:
				for i := 0; i < elem.Len(); i++ {
					if err := (&sensitiveStruct{
						subjectID: s.subjectID, // inherit parent subject ID
						val:       reflect.Indirect(elem.Index(i)),
						typ:       ssT,
					}).Replace(fn); err != nil {
						return err
					}
				}

			case ssField.isMap:
				for _, k := range elem.MapKeys() {
					mapElem := elem.MapIndex(k)
					if mapElem.IsZero() {
						continue
					}
					mapElem = reflect.Indirect(elem.MapIndex(k))
					if !mapElem.CanAddr() {
						newElem := reflect.New(mapElem.Type()).Elem()
						newElem.Set(mapElem)

						if err := (&sensitiveStruct{
							subjectID: s.subjectID, // inherit parent subject ID
							val:       newElem,
							typ:       ssT,
						}).Replace(fn); err != nil {
							return err
						}

						elem.SetMapIndex(k, newElem)
						continue
					}

					if err := (&sensitiveStruct{
						subjectID: s.subjectID,
						val:       reflect.Indirect(elem.MapIndex(k)),
						typ:       ssT,
					}).Replace(fn); err != nil {
						return err
					}
				}
			default:
				if err := (&sensitiveStruct{
					subjectID: s.subjectID,
					val:       elem,
					typ:       ssT,
				}).Replace(fn); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func scanStructType(rt reflect.Type) (sensitiveStructType, error) {
	cacheMu.Lock()
	defer cacheMu.Unlock()

	if _, ok := cache[rt]; !ok {
		c := sensitiveStructContext{seen: cache}
		ssT, err := scanStructTypeWithContext(c, rt)
		if err != nil {
			return sensitiveStructType{}, err
		}
		cache[rt] = &ssT
	}

	return *cache[rt], nil
}

func scanStructTypeWithContext(c sensitiveStructContext, rt reflect.Type) (sensitiveStructType, error) {
	sensitiveFields := make([]sensitiveField, 0)
	var subjectField sensitiveField
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		if !field.IsExported() {
			continue
		}

		tag, _ := extractTag(field.Tag)
		if tag == "" {
			continue
		}
		name, opts := parseTag(tag)
		ssField := sensitiveField{
			sf:       field,
			isSub:    name == tagSubjectID,
			isData:   name == tagData,
			isNested: name == tagDive,
			prefix:   opts["prefix"],
			kind:     opts["kind"],
			options:  opts,
		}

		switch {
		case ssField.isSub:
			if !field.Type.ConvertibleTo(stringType) {
				return sensitiveStructType{}, ErrUnsupportedFieldType
			}

			if !subjectField.IsZero() {
				return sensitiveStructType{}, ErrMultipleNestedSubjectID
			}
			subjectField = ssField

		case ssField.isData:
			tt := field.Type
			if tt.Kind() == reflect.Ptr {
				tt = tt.Elem()
			}
			if tt.Kind() != reflect.String {
				continue
			}
			sensitiveFields = append(sensitiveFields, ssField)

		case ssField.isNested:
			tt := field.Type
			if tt.Kind() == reflect.Ptr {
				tt = tt.Elem()
			}
			if tt.Kind() == reflect.Slice {
				ssField.isSlice = true
				tt = tt.Elem()
			}
			if tt.Kind() == reflect.Map {
				ssField.isMap = true
				tt = tt.Elem()
			}
			if tt.Kind() == reflect.Ptr {
				tt = tt.Elem()
			}

			_, seen := c.seen[tt]
			if !seen {
				var ssType sensitiveStructType
				var err error
				c.seen[tt] = &ssType
				ssType, err = scanStructTypeWithContext(c, tt)
				if err != nil {
					return sensitiveStructType{}, err
				}
				ssField.nestedStructType = &ssType
			} else {
				ssField.nestedStructTypeRef = tt
			}

			sensitiveFields = append(sensitiveFields, ssField)
		default:
			return sensitiveStructType{}, fmt.Errorf("invalid tag name '%s'", name)
		}
	}

	return sensitiveStructType{
		hasSensitive:    len(sensitiveFields) > 0,
		subField:        subjectField,
		sensitiveFields: sensitiveFields,
		rt:              rt,
	}, nil
}
