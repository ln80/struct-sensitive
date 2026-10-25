package sensitive_test

import (
	"fmt"
	"reflect"
)

func print(v any) {
	rv := reflect.ValueOf(v)
	fmt.Printf("%s{\n", rv.Type().Name())
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Type().Field(i)
		if !f.IsExported() {
			continue
		}
		fmt.Printf("  %s: %s,\n", f.Name, formatExample(rv.Field(i)))
	}
	fmt.Println("}")
}

func formatExample(v reflect.Value) string {
	if v.Kind() == reflect.String {
		return fmt.Sprintf("%q", v.String())
	}
	return fmt.Sprint(v.Interface())
}
