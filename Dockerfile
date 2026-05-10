FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    gcc \
    libc6-dev \
    libbpf-dev \
    linux-headers-generic \
    golang-go \
    make \
    curl \
    wget \
    git \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV GOPATH=/go
ENV PATH=$PATH:/go/bin
ENV GO111MODULE=on

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY bpf/ ./bpf/
COPY pkg/ ./pkg/
COPY cmd/ ./cmd/
COPY web/ ./web/
COPY Makefile ./

RUN make build-bpf
RUN make generate
RUN make build-go

EXPOSE 8080

CMD ["/app/output/ebpf-monitor"]