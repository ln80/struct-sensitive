package option

// Apply calls each non-nil option on t.
func Apply[T any, O ~func(*T)](t *T, opts []O) {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(t)
	}
}
