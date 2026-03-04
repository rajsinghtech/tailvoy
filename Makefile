BINARY    := tailvoy
MODULE    := github.com/rajsinghtech/tailvoy
IMAGE     := ghcr.io/rajsinghtech/tailvoy

VERSION   ?= dev
COMMIT    ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS   := -s -w

.PHONY: build test lint cover clean docker-build integration-test kind-test

build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/tailvoy/

test:
	go test -race -coverprofile=cover.out ./...

lint:
	golangci-lint run --timeout 5m

cover: test
	go tool cover -func=cover.out

clean:
	rm -f $(BINARY) cover.out

docker-build:
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg BUILD_DATE=$(BUILD_DATE) \
		-t $(IMAGE):$(VERSION) .

integration-test:
	cd integration_test && ./run-full-tests.sh

kind-test:
	./integration_test/kind/run-kind-tests.sh
