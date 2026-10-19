.PHONY: run run-debug build test-agent test-agent-loop clean tidy fmt

run:
	go run ./cmd/uplert --config configs/config.yaml

run-debug:
	UPLERT_LOG_LEVEL=debug go run ./cmd/uplert --config configs/config.yaml

build:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o bin/uplert ./cmd/uplert

test-agent:
	go run ./cmd/testagent -dir ./test_uploads -once -clean

test-agent-loop:
	go run ./cmd/testagent -dir ./test_uploads -interval 3s -step-delay 200ms

clean:
	rm -rf bin test_uploads configs/config.tmp.yaml configs/config.debug.yaml

tidy:
	go mod tidy

fmt:
	go fmt ./...