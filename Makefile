VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: test build clean
test:
	go test ./...

build: clean
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/netflix-pbrd-linux-amd64 ./cmd/netflix-pbrd
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/netflix-pbrd-linux-arm64 ./cmd/netflix-pbrd
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/netflix-pbrd-linux-armv7 ./cmd/netflix-pbrd

clean:
	rm -rf dist
