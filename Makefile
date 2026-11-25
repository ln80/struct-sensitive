

lint:
	golangci-lint run --enable misspell

FUZZTIME ?= 30s

test:
	packages=`go list ./... | grep -v masktest`; \
	go test -race -cover $$packages -coverprofile coverage.out -covermode atomic

fuzz:
	for f in $$(grep -ho '^func Fuzz[A-Za-z]*' *_test.go | cut -c6-); do \
		go test -run='^$$' -fuzz="^$$f$$" -fuzztime=$(FUZZTIME) . || exit 1; \
	done

security:
	gosec -quiet ./...
	govulncheck ./...

test/coverage:
	go tool cover -html=coverage.out

bench:
	go test -v -bench=$(b) -benchmem -memprofile mem.prof -memprofilerate=1  -run=^$$ -v

bench/profile:
	go tool pprof -alloc_objects mem.prof

doc:
	godoc -http=:6060