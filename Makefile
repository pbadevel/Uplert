.PHONY: run run-debug build tidy fmt

run:
	go run ./cmd/uplert --config configs/config.yaml

run-debug:
	@echo "Running in DEBUG mode..."
	@cp configs/config.yaml configs/config.tmp.yaml
	@sed 's/log_level: .*/log_level: debug/' configs/config.tmp.yaml > configs/config.yaml
	@go run ./cmd/uplert --config configs/config.yaml
	@sed 's/log_level: debug/log_level: info/' configs/config.yaml > configs/config.tmp.yaml
	@mv configs/config.tmp.yaml configs/config.yaml

build:
	go build -o bin/uplert ./cmd/uplert

tidy:
	go mod tidy

fmt:
	go fmt ./...
