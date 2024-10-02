

lint:
	golangci-lint run --enable misspell

test: 
	packages=`go list ./... | grep -v masktest`; \
	go test -cover $$packages -coverprofile coverage.out -covermode count

test/coverage:
	go tool cover -html=coverage.out

bench:
	go test -v -bench=$(b) -benchmem -memprofile mem.prof -memprofilerate=1  -run=^$$ -v

bench/profile:
	go tool pprof -alloc_objects mem.prof

doc:
	godoc -http=:6060