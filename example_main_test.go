package sensitive_test

import (
	"github.com/sanity-io/litter"
)

func init() {
	litter.Config.StripPackageNames = true
}

func print(v any) {
	litter.Dump(v)
}
