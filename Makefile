BINARY := bin/uplert
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.versionOverride=$(VERSION)

.PHONY: all run run-debug build test cover test-agent test-agent-loop fmt vet tidy clean

all: fmt vet test build

run:
	go run ./cmd/uplert run --config configs/config.yaml

run-debug:
	UPLERT_LOG_LEVEL=debug go run ./cmd/uplert run --config configs/config.yaml

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o $(BINARY) ./cmd/uplert

test:
	go test -race ./...

cover:
	go test -race -coverprofile=coverage.out ./... && go tool cover -html=coverage.out

test-agent:
	go run ./cmd/testagent -dir ./test_uploads -once -clean

test-agent-loop:
	go run ./cmd/testagent -dir ./test_uploads -interval 3s

fmt:
	gofmt -l -w ./cmd ./internal

vet:
	go vet ./...

tidy:
	go mod tidy

clean:
	rm -rf bin coverage.out test_uploads
