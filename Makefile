.PHONY: all build clean install run

all: build

BPF_DIR := bpf
OUTPUT_DIR := output
GO_SRC := cmd/monitor/main.go

CLANG ?= clang
GO ?= go

ARCH := $(shell uname -m | sed 's/x86_64/amd64/' | sed 's/aarch64/arm64/')

build-bpf:
	@echo "Building BPF programs..."
	@mkdir -p $(OUTPUT_DIR)
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I/usr/include \
		-I$(BPF_DIR) \
		-c $(BPF_DIR)/process.bpf.c -o $(OUTPUT_DIR)/process.bpf.o
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I/usr/include \
		-I$(BPF_DIR) \
		-c $(BPF_DIR)/network.bpf.c -o $(OUTPUT_DIR)/network.bpf.o
	$(CLANG) -O2 -g -target bpf \
		-D__TARGET_ARCH_$(ARCH) \
		-I/usr/include \
		-I$(BPF_DIR) \
		-c $(BPF_DIR)/file.bpf.c -o $(OUTPUT_DIR)/file.bpf.o

generate:
	@echo "Generating Go bindings for BPF..."
	cd pkg/bpf && go generate ./...

build-go:
	@echo "Building Go application..."
	CGO_ENABLED=0 $(GO) build -o $(OUTPUT_DIR)/ebpf-monitor $(GO_SRC)

build: build-bpf generate build-go
	@echo "Build complete."

clean:
	@echo "Cleaning..."
	rm -rf $(OUTPUT_DIR)
	rm -f pkg/bpf/bpf_bpfel.o pkg/bpf/bpf_bpfeb.o
	rm -f pkg/bpf/bpf_bpfel.go pkg/bpf/bpf_bpfeb.go

install:
	@echo "Installing..."
	install -m 755 $(OUTPUT_DIR)/ebpf-monitor /usr/local/bin/

run: build
	@echo "Running..."
	sudo $(OUTPUT_DIR)/ebpf-monitor

docker-build:
	docker build -t ebpf-monitor:latest .

docker-run:
	docker run --privileged \
		--pid=host \
		--network=host \
		-v /sys/kernel/debug:/sys/kernel/debug:ro \
		-v /sys/fs/cgroup:/sys/fs/cgroup:ro \
		-v /proc:/proc:ro \
		ebpf-monitor:latest

test:
	$(GO) test -v ./...

lint:
	$(GO) vet ./...
	golangci-lint run

fmt:
	$(GO) fmt ./...

help:
	@echo "Available targets:"
	@echo "  all       - Build everything"
	@echo "  build     - Build BPF and Go programs"
	@echo "  build-bpf - Build only BPF programs"
	@echo "  build-go  - Build only Go program"
	@echo "  generate  - Generate Go bindings"
	@echo "  clean     - Clean build artifacts"
	@echo "  install   - Install binary"
	@echo "  run       - Run the monitor"
	@echo "  docker-build - Build Docker image"
	@echo "  docker-run   - Run in Docker container"
	@echo "  test      - Run tests"
	@echo "  lint      - Run linters"
	@echo "  fmt       - Format code"