BINARY_NAME=dlp
BUILD_DIR=./bin
CMD_PATH=./cmd/dlp

.PHONY: build build-all test bench lint clean install eval-testdata

build:
	@mkdir -p $(BUILD_DIR)
	go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME) $(CMD_PATH)
	@echo "Build OK: $(BUILD_DIR)/$(BINARY_NAME)"

build-all:
	@mkdir -p $(BUILD_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-linux-amd64 $(CMD_PATH)
	GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-amd64 $(CMD_PATH)
	GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-darwin-arm64 $(CMD_PATH)
	GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY_NAME)-windows-amd64.exe $(CMD_PATH)
	@echo "Build all OK in $(BUILD_DIR)"

install: build
	cp $(BUILD_DIR)/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)

test:
	go test ./... -v -race -count=1

test-rules:
	go test ./internal/engine/... -v -run TestRules

bench:
	go test ./... -bench=. -benchmem -benchtime=10s

bench-rules:
	go test ./internal/engine/... -bench=BenchmarkRules -benchmem

eval-testdata:
	go run ./cmd/dlp scan --path ./testdata --output json --level-filter PUBLIC --output-file ./testdata/scan_result.jsonl
	go run ./scripts/eval_metrics.go --ground-truth ./testdata/ground_truth.csv --scan-jsonl ./testdata/scan_result.jsonl --out ./testdata/metrics_report.md
	@echo "Metrics report: ./testdata/metrics_report.md"

lint:
	golangci-lint run ./...

clean:
	rm -rf $(BUILD_DIR)
	go clean -testcache

docker:
	docker build -t dlp-classifier:latest .

proto:
	protoc --go_out=. --go-grpc_out=. proto/scanner.proto
