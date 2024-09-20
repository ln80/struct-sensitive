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

type Struct interface {
	Replace(fn ReplaceFunc) error
	SubjectID() string
	HasSensitive() bool
}

// Scan does scans the given value and return a representative metadata of sensitive configuration.
// It fails if the value is not a struct pointer or 'sensitive' tag is misconfigured.
//
// The returned metadata are mainly used by other hight-level functions
// in this package with some few exceptions.
func Scan(v any, requireSubject bool) (info sensitiveStruct, err error) {
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
		info = sensitiveStruct{
			typ: ssType,
		}
		return
	}

	info = sensitiveStruct{
		typ: ssType,
		val: reflect.ValueOf(v).Elem(),
	}

	if requireSubject {
		if _, err = info.resolveSubject(); err != nil {
			return
		}
	}
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
	replacement             string
	isSlice, isMap          bool
	nestedStructType        *sensitiveStructType
	nestedStructTypeRef     reflect.Type
	kind                    string
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
		if ssT == nil {
			// TBD return error instead??
			panic(fmt.Errorf("unexpected: failed to resolve sensitive field type %v", ssField))
		}

		sensitiveFieldV = reflect.Indirect(sensitiveFieldV)
		nestedSubject := ""
		switch {
		case ssField.isSlice:
			for i := 0; i < sensitiveFieldV.Len(); i++ {
				nestedSubject, _ = resolveSubject(*ssT, sensitiveFieldV.Index(i))
				if nestedSubject != "" {
					break
				}
			}
		case ssField.isMap:
			for _, k := range sensitiveFieldV.MapKeys() {
				nestedSubject, _ = resolveSubject(*ssT, sensitiveFieldV.MapIndex(k))
				if nestedSubject != "" {
					break
				}
			}
		default:
			nestedSubject, _ = resolveSubject(*ssT, sensitiveFieldV)
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

type FieldReplace struct {
	SubjectID   string
	Name        string
	RType       reflect.Type
	Replacement string
	Kind        string
}

type ReplaceFunc func(fr FieldReplace, val string) (string, error)

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
				SubjectID:   s.subjectID,
				RType:       ssField.sf.Type,
				Replacement: ssField.replacement,
				Kind:        ssField.kind,
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

			if ssTPtr == nil {
				panic(fmt.Errorf("unexpected: failed to resolve sensitive field type %v", ssField))
			}
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

		tag := extractTag(field.Tag)
		if tag == "" {
			continue
		}
		name, opts := parseTag(tag)
		ssField := sensitiveField{
			sf:          field,
			isSub:       name == tagSubjectID,
			isData:      name == tagData,
			isNested:    name == tagDive,
			prefix:      opts["prefix"],
			replacement: opts["replace"],
			kind:        opts["kind"],
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
		}
	}

	return sensitiveStructType{
		hasSensitive:    len(sensitiveFields) > 0,
		subField:        subjectField,
		sensitiveFields: sensitiveFields,
		rt:              rt,
	}, nil
}
