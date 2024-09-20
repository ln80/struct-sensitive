

lint:
	golangci-lint run --enable misspell

test: 
	go test -race -cover ./... -coverprofile coverage.out -covermode atomic

test/coverage:
	go tool cover -html=coverage.out

bench:
	go test -v -bench=$(b) -benchmem -memprofile mem.prof -memprofilerate=1  -run=^$$ -v

bench/profile:
	go tool pprof -alloc_objects mem.prof