HOSTNAME=registry.terraform.io
NAMESPACE=phaezer
NAME=kubeseal
BINARY=terraform-provider-${NAME}
VERSION=0.1.0
OS_ARCH=$(shell go env GOOS)_$(shell go env GOARCH)

default: build

build:
	go build -o ${BINARY}

install: build
	mkdir -p ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}
	cp ${BINARY} ~/.terraform.d/plugins/${HOSTNAME}/${NAMESPACE}/${NAME}/${VERSION}/${OS_ARCH}/

test:
	go test ./... -v

testacc:
	TF_ACC=1 go test ./... -v -timeout 120m

fmt:
	go fmt ./...

lint:
	golangci-lint run ./...

.PHONY: default build install test testacc fmt lint
