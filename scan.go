package sensitive

import (
	"errors"
	"fmt"
	"maps"
	"reflect"
	"sort"
	"strconv"
	"sync"
)

var (
	ErrInvalidTagConfiguration = errors.New("invalid 'sensitive' tag configuration")
	ErrUnsupportedType         = errors.New("unsupported 'sensitive' type")
	ErrUnsupportedFieldType    = errors.New("unsupported 'sensitive' field type")
	ErrMultipleSubjectID       = errors.New("multiple subjectID fields")
	ErrSubjectIDNotFound       = errors.New("subject ID is not found")
	ErrCycle                   = errors.New("cycle in sensitive value")
	ErrMaxDepth                = errors.New("sensitive value is nested too deeply")
)

const maxWalkDepth = 10000

// Struct provides an accessor for sensitive struct fields and subject identifiers.
type Struct interface {
	// Replace accepts a replacement function and applies it to each sensitive data field.
	// It writes nothing when fn returns an error.
	Replace(fn ReplaceFunc) error

	// Plan visits each sensitive field and calls fn without writing.
	// Commit on the result writes every replacement. A callback error writes nothing.
	Plan(fn ReplaceFunc) (Replacement, error)

	// SubjectID returns the subject Scan observed: the root struct's own
	// subject, or the single nested subject when the root has none and every
	// nested subject agrees. It is empty when nested subjects disagree, and
	// panics when no subject can be resolved. Changing the struct after Scan
	// does not change this result.
	SubjectID() string

	// HasSensitive indicates whether the struct contains sensitive data fields.
	HasSensitive() bool

	private()
}

// Replacement is a set of field updates collected by [Struct.Plan].
// Commit applies every update. It writes nothing until then.
type Replacement interface {
	Commit() error

	private()
}

// FieldReplace contains metadata for sensitive fields.
type FieldReplace struct {
	// SubjectID is the subject of the struct that owns the field.
	// When that struct has no subjectID field, SubjectID is the parent subject.
	// This field may be empty if it is not required by the calling function.
	SubjectID string

	// Name is the name of the sensitive field.
	Name string

	// Path is the field location, such as Email, Members[1].Email, or Tags[0].
	// A map element uses a stable index. The map key is not part of the path.
	Path string

	// RType is the original type of the sensitive field.
	// Note that this type must be convertible to a string.
	RType reflect.Type

	// Kind is the user-defined type of sensitive data, defined as an option in the 'sensitive' tag.
	Kind string

	// Options is a copy of the options specified in the 'sensitive' tag.
	// Changing it does not affect other values.
	Options TagOptions
}

// ReplaceFunc is a callback function executed by the [Struct.Replace] method.
// It receives the original value of the sensitive field, converted to a string,
// and returns the new value as a string along with any error that may occur.
type ReplaceFunc func(fr FieldReplace, val string) (string, error)

// Scan inspects the given value and returns an accessor for the sensitive struct.
// It returns an error if the value is not a pointer to a struct or if the 'sensitive' tag is misconfigured.
//
// The [Struct] accessor and the [Scan] function are low-level components.
// In most cases, you should consider using the [Redact] or [Mask] functions instead.
func Scan(v any, requireSubject bool) (accessor Struct, err error) {
	defer func() {
		catchPanic(&err)
		// Tag and type failures share one sentinel. A bad record, a cycle,
		// and a walk that is too deep stay as themselves.
		if err != nil && !recordError(err) {
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
	tt = tt.Elem()
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
		// The struct does not contain sensitive data, so there is no need to resolve the subject ID value.
		// Therefore, calling 'reflect.ValueOf' is unnecessary due to its associated cost.
		accessor = sensitiveStruct{
			typ: ssType,
		}
		return
	}

	structValue := sensitiveStruct{
		typ: ssType,
		val: reflect.ValueOf(v).Elem(),
	}
	if err = walkStructs(ssType, structValue.val, newValueWalk()); err != nil {
		return
	}
	sub, st, err := classifyRoot(ssType, structValue.val)
	if err != nil {
		return
	}
	switch st {
	case subjectOne:
		structValue.subjectID = sub
		structValue.hasSubject = true
	case subjectMany:
		structValue.hasSubject = true
	}

	if requireSubject {
		if err = ensureSubjects(ssType, structValue.val, "", false, newValueWalk()); err != nil {
			return
		}
	}

	accessor = structValue
	return
}

// catchPanic converts a panic into an error. Value cycles and excessive
// nesting are reported as ErrCycle and ErrMaxDepth before they reach the
// stack limit, which recover cannot catch.
func catchPanic(err *error) {
	if r := recover(); r != nil {
		*err = fmt.Errorf("struct-sensitive: %v", r)
	}
}

// recordError reports errors that describe the value rather than its tags.
func recordError(err error) bool {
	return errors.Is(err, ErrUnsupportedType) ||
		errors.Is(err, ErrSubjectIDNotFound) ||
		errors.Is(err, ErrCycle) ||
		errors.Is(err, ErrMaxDepth)
}

type walkKey struct {
	addr uintptr
	typ  reflect.Type
}

type valueWalk struct {
	seen  map[walkKey]struct{}
	depth int
}

func newValueWalk() *valueWalk {
	return &valueWalk{seen: make(map[walkKey]struct{})}
}

// enter records an addressable struct. The same address and type again is a cycle.
// The key includes the type because an embedded struct at offset zero shares its
// parent's address. Depth counts every struct visited, addressable or not.
func (w *valueWalk) enter(v reflect.Value) error {
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return nil
	}
	if v.CanAddr() {
		key := walkKey{addr: v.Addr().Pointer(), typ: v.Type()}
		if _, ok := w.seen[key]; ok {
			return ErrCycle
		}
		w.seen[key] = struct{}{}
	}
	w.depth++
	if w.depth > maxWalkDepth {
		return ErrMaxDepth
	}
	return nil
}

var (
	stringType = reflect.TypeFor[string]()
)

// isSubjectIDType reports whether t is a valid subjectID field type.
// Accepted types are string kinds (including named strings), slices of
// bytes (including named []byte), and one pointer to either.
// Other kinds that Go can convert to string, such as integers and []rune,
// are rejected.
func isSubjectIDType(t reflect.Type) bool {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.String {
		return true
	}
	return t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8
}

// subjectIDValue returns the subject text for a field accepted by isSubjectIDType.
// []byte is converted to string; Value.String() would return a placeholder
// such as "<[]uint8 Value>" for every slice.
func subjectIDValue(v reflect.Value) string {
	v = reflect.Indirect(v)
	switch v.Kind() {
	case reflect.String:
		return v.String()
	case reflect.Slice:
		if v.IsNil() {
			return ""
		}
		return v.Convert(stringType).String()
	default:
		return ""
	}
}

func isByteSlice(t reflect.Type) bool {
	return t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8
}

func isRoundTripData(t reflect.Type) bool {
	return t.Kind() == reflect.String || isByteSlice(t)
}

// classifyData reports whether t is an accepted data field.
// slice is true when each element is visited, rather than the field as one value.
// []byte is one value. []string, []*string, and [][]byte are slices.
func classifyData(t reflect.Type) (slice bool, ok bool) {
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if isRoundTripData(t) {
		return false, true
	}
	if t.Kind() == reflect.Slice && !isByteSlice(t) {
		elem := t.Elem()
		if elem.Kind() == reflect.Pointer {
			elem = elem.Elem()
		}
		if isRoundTripData(elem) {
			return true, true
		}
	}
	return false, false
}

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
	isDataSlice             bool
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
	return f.sf.Name == ""
}

type sensitiveStructType struct {
	hasSensitive    bool
	subField        sensitiveField
	sensitiveFields []sensitiveField
	rt              reflect.Type
}

type sensitiveStruct struct {
	typ        sensitiveStructType
	val        reflect.Value
	subjectID  string
	hasSubject bool
}

func (ps sensitiveStruct) private() {}

var _ Struct = &sensitiveStruct{}

type subjectState int

const (
	subjectNone subjectState = iota
	subjectOne
	subjectMany
)

// readSubject returns the subject declared on pt itself.
// A nil embedded pointer yields ok == false.
func readSubject(pt sensitiveStructType, pv reflect.Value) (string, bool) {
	if pt.subField.IsZero() || !pv.IsValid() {
		return "", false
	}
	v := pv
	for _, x := range pt.subField.sf.Index {
		if v.Kind() == reflect.Pointer || v.Kind() == reflect.Interface {
			if v.IsNil() {
				return "", false
			}
			v = v.Elem()
		}
		if !v.IsValid() || v.Kind() != reflect.Struct {
			return "", false
		}
		v = v.Field(x)
	}
	if !v.IsValid() {
		return "", false
	}
	return pt.subField.prefix + subjectIDValue(v), true
}

func nestedTypeOf(f sensitiveField) (sensitiveStructType, bool) {
	cacheMu.RLock()
	defer cacheMu.RUnlock()
	p := f.getType(cache)
	if p == nil {
		return sensitiveStructType{}, false
	}
	return *p, true
}

// nestedSubjects lists the subjects owned by pt or, when pt has none, by its elements.
func nestedSubjects(pt sensitiveStructType, pv reflect.Value, w *valueWalk) ([]string, error) {
	if !pv.IsValid() {
		return nil, nil
	}
	if err := w.enter(pv); err != nil {
		return nil, err
	}
	if !pt.subField.IsZero() {
		if s, ok := readSubject(pt, pv); ok && s != "" {
			return []string{s}, nil
		}
		return nil, nil
	}
	var out []string
	for _, f := range pt.sensitiveFields {
		if !f.isNested {
			continue
		}
		fv := pv.FieldByIndex(f.sf.Index)
		if !fv.IsValid() || fv.IsZero() {
			continue
		}
		nt, ok := nestedTypeOf(f)
		if !ok {
			continue
		}
		subs, err := subjectsOfField(nt, fv, f, w)
		if err != nil {
			return nil, err
		}
		out = append(out, subs...)
	}
	return out, nil
}

func subjectsOfField(nt sensitiveStructType, fv reflect.Value, f sensitiveField, w *valueWalk) ([]string, error) {
	var out []string
	switch {
	case f.isSlice:
		fv = reflect.Indirect(fv)
		if !fv.IsValid() || fv.Kind() != reflect.Slice {
			return nil, nil
		}
		for i := 0; i < fv.Len(); i++ {
			el, ok := derefStruct(fv.Index(i))
			if !ok {
				continue
			}
			subs, err := nestedSubjects(nt, el, w)
			if err != nil {
				return nil, err
			}
			out = append(out, subs...)
		}
	case f.isMap:
		fv = reflect.Indirect(fv)
		if !fv.IsValid() || fv.Kind() != reflect.Map {
			return nil, nil
		}
		for _, k := range fv.MapKeys() {
			el, ok := derefStruct(fv.MapIndex(k))
			if !ok {
				continue
			}
			subs, err := nestedSubjects(nt, el, w)
			if err != nil {
				return nil, err
			}
			out = append(out, subs...)
		}
	default:
		el, ok := derefStruct(fv)
		if !ok {
			return nil, nil
		}
		return nestedSubjects(nt, el, w)
	}
	return out, nil
}

func uniqueNested(pt sensitiveStructType, pv reflect.Value) (string, subjectState, error) {
	subs, err := nestedSubjects(pt, pv, newValueWalk())
	if err != nil {
		return "", subjectNone, err
	}
	if len(subs) == 0 {
		return "", subjectNone, nil
	}
	first := subs[0]
	for _, s := range subs[1:] {
		if s != first {
			return "", subjectMany, nil
		}
	}
	return first, subjectOne, nil
}

func classifyRoot(pt sensitiveStructType, pv reflect.Value) (string, subjectState, error) {
	if !pt.subField.IsZero() {
		s, ok := readSubject(pt, pv)
		if !ok {
			return "", subjectOne, nil
		}
		return s, subjectOne, nil
	}
	return uniqueNested(pt, pv)
}

// effectiveSubject is the subject used for data fields of this struct.
// An own subjectID wins, including when it is empty. Otherwise the parent
// subject is used. The root, which has no parent, adopts the nested subject
// when every nested subject is the same.
func effectiveSubject(pt sensitiveStructType, pv reflect.Value, inherited string, hasInherited bool) (string, error) {
	if !pt.subField.IsZero() {
		s, ok := readSubject(pt, pv)
		if !ok {
			return "", nil
		}
		return s, nil
	}
	if hasInherited {
		return inherited, nil
	}
	sub, st, err := uniqueNested(pt, pv)
	if err != nil {
		return "", err
	}
	if st == subjectOne {
		return sub, nil
	}
	return "", nil
}

func ensureSubjects(pt sensitiveStructType, pv reflect.Value, inherited string, hasInherited bool, w *valueWalk) error {
	if !pv.IsValid() {
		return nil
	}
	if err := w.enter(pv); err != nil {
		return err
	}
	subject, err := effectiveSubject(pt, pv, inherited, hasInherited)
	if err != nil {
		return err
	}
	for _, f := range pt.sensitiveFields {
		if f.isData && subject == "" {
			return fmt.Errorf("%w in '%v'", ErrSubjectIDNotFound, pt.rt)
		}
	}
	for _, f := range pt.sensitiveFields {
		if !f.isNested {
			continue
		}
		fv := pv.FieldByIndex(f.sf.Index)
		if !fv.IsValid() || fv.IsZero() {
			continue
		}
		nt, ok := nestedTypeOf(f)
		if !ok {
			return errors.New("struct-sensitive: cached nested struct type is unexpectedly nil")
		}
		if err := ensureFieldSubjects(nt, fv, f, subject, w); err != nil {
			return err
		}
	}
	return nil
}

func ensureFieldSubjects(nt sensitiveStructType, fv reflect.Value, f sensitiveField, subject string, w *valueWalk) error {
	switch {
	case f.isSlice:
		fv = reflect.Indirect(fv)
		if !fv.IsValid() || fv.Kind() != reflect.Slice {
			return nil
		}
		for i := 0; i < fv.Len(); i++ {
			el, ok := derefStruct(fv.Index(i))
			if !ok {
				continue
			}
			if err := ensureSubjects(nt, el, subject, true, w); err != nil {
				return err
			}
		}
	case f.isMap:
		fv = reflect.Indirect(fv)
		if !fv.IsValid() || fv.Kind() != reflect.Map {
			return nil
		}
		for _, k := range fv.MapKeys() {
			el, ok := derefStruct(fv.MapIndex(k))
			if !ok {
				continue
			}
			if err := ensureSubjects(nt, el, subject, true, w); err != nil {
				return err
			}
		}
	default:
		el, ok := derefStruct(fv)
		if !ok {
			return nil
		}
		if err := ensureSubjects(nt, el, subject, true, w); err != nil {
			return err
		}
	}
	return nil
}

func walkStructs(pt sensitiveStructType, pv reflect.Value, w *valueWalk) error {
	if !pv.IsValid() {
		return nil
	}
	if err := w.enter(pv); err != nil {
		return err
	}
	for _, f := range pt.sensitiveFields {
		if !f.isNested {
			continue
		}
		fv := pv.FieldByIndex(f.sf.Index)
		if !fv.IsValid() || fv.IsZero() {
			continue
		}
		nt, ok := nestedTypeOf(f)
		if !ok {
			continue
		}
		if err := walkField(nt, fv, f, w); err != nil {
			return err
		}
	}
	return nil
}

func walkField(nt sensitiveStructType, fv reflect.Value, f sensitiveField, w *valueWalk) error {
	switch {
	case f.isSlice:
		fv = reflect.Indirect(fv)
		if !fv.IsValid() || fv.Kind() != reflect.Slice {
			return nil
		}
		for i := 0; i < fv.Len(); i++ {
			el, ok := derefStruct(fv.Index(i))
			if !ok {
				continue
			}
			if err := walkStructs(nt, el, w); err != nil {
				return err
			}
		}
	case f.isMap:
		fv = reflect.Indirect(fv)
		if !fv.IsValid() || fv.Kind() != reflect.Map {
			return nil
		}
		for _, k := range fv.MapKeys() {
			el, ok := derefStruct(fv.MapIndex(k))
			if !ok {
				continue
			}
			if err := walkStructs(nt, el, w); err != nil {
				return err
			}
		}
	default:
		el, ok := derefStruct(fv)
		if !ok {
			return nil
		}
		return walkStructs(nt, el, w)
	}
	return nil
}

func derefStruct(v reflect.Value) (reflect.Value, bool) {
	if !v.IsValid() {
		return v, false
	}
	v = reflect.Indirect(v)
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return v, false
	}
	return v, true
}

func (ss sensitiveStruct) SubjectID() string {
	// Scan stores the subject it observed. Later writes to the struct do not
	// change this result, and a missing subject does not walk the value again.
	if !ss.hasSubject {
		panic(fmt.Errorf("%w in '%v'", ErrSubjectIDNotFound, ss.typ.rt))
	}
	return ss.subjectID
}

func (ss sensitiveStruct) HasSensitive() bool {
	return ss.typ.hasSensitive
}

type fieldWrite struct {
	elem   reflect.Value
	newVal string
}

type mapAssign struct {
	m, key, elem reflect.Value
}

type replacement struct {
	writes []fieldWrite
	maps   []mapAssign
}

func (r *replacement) private() {}

func (r *replacement) Commit() error {
	for _, w := range r.writes {
		if !w.elem.IsValid() || !w.elem.CanSet() {
			continue
		}
		// Zero the original []byte backing array when the value is replaced.
		// A string copy cannot be scrubbed.
		if isByteSlice(w.elem.Type()) && !w.elem.IsNil() {
			for i := range w.elem.Bytes() {
				w.elem.Bytes()[i] = 0
			}
		}
		setDataString(w.elem, w.newVal)
	}
	for _, m := range r.maps {
		m.m.SetMapIndex(m.key, m.elem)
	}
	return nil
}

func (s sensitiveStruct) Replace(fn ReplaceFunc) (err error) {
	defer catchPanic(&err)
	rep, err := s.Plan(fn)
	if err != nil {
		return err
	}
	err = rep.Commit()
	return err
}

func (s sensitiveStruct) Plan(fn ReplaceFunc) (rep Replacement, err error) {
	defer catchPanic(&err)
	rec := &replacement{}
	if err = s.collect(fn, "", rec, newValueWalk()); err != nil {
		return nil, err
	}
	return rec, nil
}

func (s sensitiveStruct) collect(fn ReplaceFunc, path string, rec *replacement, w *valueWalk) error {
	if !s.val.IsValid() {
		return nil
	}
	if err := w.enter(s.val); err != nil {
		return err
	}
	subject, err := effectiveSubject(s.typ, s.val, s.subjectID, s.hasSubject)
	if err != nil {
		return err
	}
	for _, ssField := range s.typ.sensitiveFields {
		v := s.val.FieldByIndex(ssField.sf.Index)
		if !v.IsValid() || v.IsZero() {
			continue
		}
		if ssField.isData && !v.CanSet() {
			continue
		}
		elem := reflect.Indirect(v)
		if !elem.IsValid() {
			continue
		}
		p := fieldPath(path, ssField.sf.Name)

		switch {
		case ssField.isData && ssField.isDataSlice:
			if err := replaceDataSlice(ssField, elem, subject, p, fn, rec); err != nil {
				return err
			}
		case ssField.isData:
			if err := replaceDataValue(ssField, elem, subject, p, fn, rec); err != nil {
				return err
			}
		case ssField.isNested:
			if err := replaceNested(ssField, elem, subject, p, fn, rec, w); err != nil {
				return err
			}
		}
	}
	return nil
}

func replaceDataSlice(field sensitiveField, elem reflect.Value, subject, path string, fn ReplaceFunc, rec *replacement) error {
	if elem.Kind() != reflect.Slice {
		return nil
	}
	for i := 0; i < elem.Len(); i++ {
		el := reflect.Indirect(elem.Index(i))
		if !el.IsValid() {
			continue
		}
		if err := replaceDataValue(field, el, subject, indexPath(path, i), fn, rec); err != nil {
			return err
		}
	}
	return nil
}

func replaceDataValue(field sensitiveField, elem reflect.Value, subject, path string, fn ReplaceFunc, rec *replacement) error {
	if !elem.IsValid() {
		return nil
	}
	val := dataString(elem)
	newVal, err := fn(FieldReplace{
		SubjectID: subject,
		Name:      field.sf.Name,
		Path:      path,
		RType:     field.sf.Type,
		Kind:      field.kind,
		Options:   maps.Clone(field.options),
	}, val)
	if err != nil {
		return err
	}
	if newVal == val || !elem.CanSet() {
		return nil
	}
	rec.writes = append(rec.writes, fieldWrite{elem: elem, newVal: newVal})
	return nil
}

func dataString(v reflect.Value) string {
	if !v.IsValid() {
		return ""
	}
	if v.Kind() == reflect.String {
		return v.String()
	}
	if v.Type().ConvertibleTo(stringType) {
		return v.Convert(stringType).String()
	}
	return v.String()
}

func setDataString(elem reflect.Value, newVal string) {
	switch elem.Kind() {
	case reflect.String:
		elem.SetString(newVal)
	default:
		vv := reflect.ValueOf(newVal)
		if vv.IsValid() && vv.Type().ConvertibleTo(elem.Type()) {
			elem.Set(vv.Convert(elem.Type()))
		}
	}
}

func replaceNested(field sensitiveField, elem reflect.Value, subject, path string, fn ReplaceFunc, rec *replacement, w *valueWalk) error {
	nt, ok := nestedTypeOf(field)
	if !ok {
		return errors.New("struct-sensitive: cached nested struct type is unexpectedly nil")
	}
	if !nt.hasSensitive {
		return nil
	}
	visit := func(val reflect.Value, childPath string) error {
		return (sensitiveStruct{
			typ:        nt,
			val:        val,
			subjectID:  subject,
			hasSubject: true,
		}).collect(fn, childPath, rec, w)
	}
	switch {
	case field.isSlice:
		if elem.Kind() != reflect.Slice {
			return nil
		}
		for i := 0; i < elem.Len(); i++ {
			el, ok := derefStruct(elem.Index(i))
			if !ok {
				continue
			}
			if err := visit(el, indexPath(path, i)); err != nil {
				return err
			}
		}
	case field.isMap:
		if elem.Kind() != reflect.Map {
			return nil
		}
		keys := elem.MapKeys()
		sort.Slice(keys, func(i, j int) bool {
			return fmt.Sprint(keys[i].Interface()) < fmt.Sprint(keys[j].Interface())
		})
		for i, k := range keys {
			el, ok := derefStruct(elem.MapIndex(k))
			if !ok {
				continue
			}
			childPath := indexPath(path, i)
			if !el.CanAddr() {
				newElem := reflect.New(el.Type()).Elem()
				newElem.Set(el)
				if err := visit(newElem, childPath); err != nil {
					return err
				}
				rec.maps = append(rec.maps, mapAssign{m: elem, key: k, elem: newElem})
				continue
			}
			if err := visit(el, childPath); err != nil {
				return err
			}
		}
	default:
		el, ok := derefStruct(elem)
		if !ok {
			return nil
		}
		if err := visit(el, path); err != nil {
			return err
		}
	}
	return nil
}

func indexPath(path string, i int) string {
	return path + "[" + strconv.Itoa(i) + "]"
}

func scanStructType(rt reflect.Type) (sensitiveStructType, error) {
	// Fast path: check cache with read lock (avoids exclusive lock contention on cache hits)
	cacheMu.RLock()
	if cached, ok := cache[rt]; ok {
		cacheMu.RUnlock()
		return *cached, nil
	}
	cacheMu.RUnlock()

	// Slow path: acquire exclusive lock for cache population
	cacheMu.Lock()
	defer cacheMu.Unlock()
	if cached, ok := cache[rt]; ok {
		return *cached, nil
	}

	local := make(map[reflect.Type]*sensitiveStructType)
	c := sensitiveStructContext{seen: local}
	ssT, err := scanStructTypeWithContext(c, rt, "")
	if err != nil {
		return sensitiveStructType{}, err
	}
	for k, v := range local {
		cache[k] = v
	}
	cache[rt] = &ssT
	return *cache[rt], nil
}

func fieldPath(path, name string) string {
	if path == "" {
		return name
	}
	return path + "." + name
}

func embeddedStruct(field reflect.StructField) bool {
	if !field.Anonymous {
		return false
	}
	t := field.Type
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return t.Kind() == reflect.Struct
}

func scanStructTypeWithContext(c sensitiveStructContext, rt reflect.Type, path string) (sensitiveStructType, error) {
	sensitiveFields := make([]sensitiveField, 0, rt.NumField())
	var subjectField sensitiveField
	for i := 0; i < rt.NumField(); i++ {
		field := rt.Field(i)
		tag, _, err := extractTag(field.Tag)
		if err != nil {
			return sensitiveStructType{}, err
		}
		if !field.IsExported() && !field.Anonymous {
			if tag != "" {
				return sensitiveStructType{}, fmt.Errorf("%w: unexported %s %s", ErrUnsupportedFieldType, fieldPath(path, field.Name), field.Type)
			}
			continue
		}
		if tag == "" {
			if !embeddedStruct(field) {
				continue
			}
			ssField := sensitiveField{sf: field, isNested: true}
			if err := attachDive(c, &ssField, &subjectField, field, path); err != nil {
				return sensitiveStructType{}, err
			}
			sensitiveFields = append(sensitiveFields, ssField)
			continue
		}

		name, opts, err := parseTag(tag)
		if err != nil {
			return sensitiveStructType{}, err
		}
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
			// String kinds and []byte only. Integers are convertible to string,
			// but that conversion is a rune conversion, so every numeric id would
			// collapse or turn into a character. Reject them here.
			if !isSubjectIDType(field.Type) {
				return sensitiveStructType{}, fmt.Errorf("%w: subjectID %s %s", ErrUnsupportedFieldType, fieldPath(path, field.Name), field.Type)
			}
			if !subjectField.IsZero() {
				return sensitiveStructType{}, ErrMultipleSubjectID
			}
			subjectField = ssField

		case ssField.isData:
			slice, ok := classifyData(field.Type)
			if !ok {
				return sensitiveStructType{}, fmt.Errorf("%w: data %s %s", ErrUnsupportedFieldType, fieldPath(path, field.Name), field.Type)
			}
			ssField.isDataSlice = slice
			sensitiveFields = append(sensitiveFields, ssField)

		case ssField.isNested:
			if err := attachDive(c, &ssField, &subjectField, field, path); err != nil {
				return sensitiveStructType{}, err
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

func attachDive(c sensitiveStructContext, ssField *sensitiveField, subjectField *sensitiveField, field reflect.StructField, path string) error {
	tt := field.Type
	if tt.Kind() == reflect.Pointer {
		tt = tt.Elem()
	}
	switch tt.Kind() {
	case reflect.Slice:
		ssField.isSlice = true
		tt = tt.Elem()
	case reflect.Map:
		ssField.isMap = true
		tt = tt.Elem()
	}
	if tt.Kind() == reflect.Pointer {
		tt = tt.Elem()
	}
	if tt.Kind() != reflect.Struct {
		return fmt.Errorf("%w: dive %s %s", ErrUnsupportedFieldType, fieldPath(path, field.Name), field.Type)
	}

	nested, err := attachNested(c, ssField, tt, fieldPath(path, field.Name))
	if err != nil {
		return err
	}
	return promoteSubject(subjectField, field, nested)
}

func attachNested(c sensitiveStructContext, ssField *sensitiveField, tt reflect.Type, path string) (*sensitiveStructType, error) {
	if cached, ok := cache[tt]; ok {
		ssField.nestedStructType = cached
		return cached, nil
	}
	if existing, ok := c.seen[tt]; ok {
		ssField.nestedStructTypeRef = tt
		return existing, nil
	}
	var ssType sensitiveStructType
	c.seen[tt] = &ssType
	var err error
	ssType, err = scanStructTypeWithContext(c, tt, path)
	if err != nil {
		return nil, err
	}
	ssField.nestedStructType = &ssType
	return &ssType, nil
}

// promoteSubject copies an anonymous embedded struct's subjectID onto the parent
// so the parent's own subject is the embedded field. A second subject on the
// same struct is still ErrMultipleSubjectID.
func promoteSubject(subjectField *sensitiveField, field reflect.StructField, nested *sensitiveStructType) error {
	if !field.Anonymous || nested == nil || nested.subField.IsZero() {
		return nil
	}
	if !subjectField.IsZero() {
		return ErrMultipleSubjectID
	}
	promoted := nested.subField
	idx := make([]int, 0, len(field.Index)+len(nested.subField.sf.Index))
	idx = append(idx, field.Index...)
	idx = append(idx, nested.subField.sf.Index...)
	promoted.sf.Index = idx
	*subjectField = promoted
	return nil
}
