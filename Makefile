VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: fmt vet test build cross clean

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test ./...

build:
	@mkdir -p bin
	go build -trimpath -ldflags "$(LDFLAGS)" -o bin/bercert ./cmd/bercert

cross:
	@mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/bercert-linux-amd64 ./cmd/bercert

clean:
	rm -rf bin dist
