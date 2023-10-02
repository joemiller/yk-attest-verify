deps:
	@go get

lint:
	@golangci-lint run -v --timeout=3m
	@if command -v goreleaser >/dev/null; then \
		goreleaser check; \
	else \
		echo "goreleaser not installed, skipping goreleaser linting"; \
	fi

test:
	@go test -coverprofile=cover.out -v ./...

cov:
	@go tool cover -html=cover.out

build-linux:
	@GOOS=linux GOOARCH=amd64 go build .

build:
	@go build .

release:
	@goreleaser $(GORELEASER_ARGS)

snapshot: GORELEASER_ARGS= --clean --snapshot
snapshot: release

todo:
	@grep \
		--exclude-dir=vendor \
		--exclude-dir=dist \
		--exclude-dir=Attic \
		--text \
		--color \
		-nRo -E 'TODO.*' .

.PHONY: build build-linux test snapshot todo
