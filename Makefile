BINARY  := dnsss-server
GO      ?= go

.PHONY: build test vet lint migrate-up seed run clean

build:
	$(GO) build -o bin/$(BINARY) ./cmd/server

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

lint: vet
	@command -v golangci-lint >/dev/null && golangci-lint run ./... || echo "golangci-lint 未安装,跳过"

migrate-up:
	DNSSS_DB_DSN="$(DNSSS_DB_DSN)" ./bin/$(BINARY) -migrate

seed:
	DNSSS_DB_DSN="$(DNSSS_DB_DSN)" DNSSS_JWT_SECRET="$(DNSSS_JWT_SECRET)" DNSSS_ADMIN_PASSWORD="$(DNSSS_ADMIN_PASSWORD)" ./bin/$(BINARY) -seed

run: build
	./bin/$(BINARY)

clean:
	rm -rf bin
