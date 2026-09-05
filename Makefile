# SSLScout Makefile
#
# Written to work with both GNU make (Linux, macOS) and BSD make (bmake,
# FreeBSD). That is why there is no `ifeq`, no `$(shell ...)`, no `!=` and no
# `.DEFAULT_GOAL`: everything that needs a shell happens inside a recipe.
# The default target is the first one in the file (`help`), which holds in both.

GO           = go
BINARY       = sslscout
PKG          = ./cmd/sslscout
REPORT       = public/report.json
SERVE_ADDR   = :8080
DOCKER_IMAGE = sslscout
DOCKER_TAG   = latest
COMPOSE      = docker compose

# Version injected into main.version. When empty it is discovered through
# `git describe` at build time (falling back to "dev" outside a Git repository).
VERSION      =

.PHONY: help build run test fmt vet lint clean serve docker up down logs

help:
	@echo "SSLScout - available targets:"
	@echo ""
	@echo "  make build     build $(BINARY) with the version injected into main.version"
	@echo "  make run       build and run one check (writes $(REPORT))"
	@echo "  make serve     build, check and serve the dashboard on $(SERVE_ADDR)"
	@echo "  make test      go test -race ./..."
	@echo "  make fmt       format the code with gofmt -w"
	@echo "  make vet       go vet ./..."
	@echo "  make lint      fail on any badly formatted file, then run go vet"
	@echo "  make clean     remove the binary, coverage artifacts and $(REPORT)"
	@echo "  make docker    build the image $(DOCKER_IMAGE):$(DOCKER_TAG)"
	@echo "  make up        docker compose up -d (checker + nginx dashboard)"
	@echo "  make down      docker compose down"
	@echo "  make logs      follow the checker logs"
	@echo "  make help      show this help (default target)"
	@echo ""
	@echo "Variables: GO, VERSION, SERVE_ADDR, DOCKER_IMAGE, DOCKER_TAG, COMPOSE"
	@echo "Example:   make build VERSION=1.0.0"

build:
	@v="$(VERSION)"; \
	if [ -z "$$v" ]; then \
		v=`git describe --tags --always --dirty 2>/dev/null` || v=""; \
	fi; \
	if [ -z "$$v" ]; then v="dev"; fi; \
	echo "==> building $(BINARY) $$v"; \
	$(GO) build -trimpath -ldflags "-s -w -X main.version=$$v" -o $(BINARY) $(PKG)

run: build
	./$(BINARY)

serve: build
	./$(BINARY) -serve $(SERVE_ADDR)

test:
	$(GO) test -race ./...

fmt:
	gofmt -w -s .

vet:
	$(GO) vet ./...

lint:
	@out=`gofmt -l .`; \
	if [ -n "$$out" ]; then \
		echo "gofmt: badly formatted files (run 'make fmt'):"; \
		echo "$$out"; \
		exit 1; \
	fi; \
	echo "gofmt: ok"
	$(GO) vet ./...

clean:
	rm -f $(BINARY) coverage.out coverage.html $(REPORT)

docker:
	@v="$(VERSION)"; \
	if [ -z "$$v" ]; then \
		v=`git describe --tags --always --dirty 2>/dev/null` || v=""; \
	fi; \
	if [ -z "$$v" ]; then v="dev"; fi; \
	docker build --build-arg VERSION="$$v" -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

up:
	@if [ ! -f config.json ]; then \
		echo "config.json is missing - create it before the first 'up',"; \
		echo "otherwise Docker will create a DIRECTORY in its place:"; \
		echo "  cp config.example.json config.json && chmod 600 config.json"; \
		exit 1; \
	fi
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f sslscout
