package option

func Apply[T any](t *T, opts []func(*T)) {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(t)
	}
}
