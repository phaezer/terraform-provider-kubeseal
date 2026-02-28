default: fmt lint install generate

build:
	go build -v ./...

generate:
	cd tools; go generate ./...

install: build
	go install -v ./...

test:
	go test -v -cover -timeout=120s -parallel=10 ./...

testacc:
	TF_ACC=1 go test -v -cover -timeout 120m ./...

fmt:
	go fmt ./...

lint:
	golangci-lint run ./...

.PHONY: default build install test testacc fmt lint generate
