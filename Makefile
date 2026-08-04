VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: test build package clean
test:
	go test ./...

build: clean
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/netflix-pbrd-linux-amd64 ./cmd/netflix-pbrd
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/netflix-pbrd-linux-arm64 ./cmd/netflix-pbrd
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/netflix-pbrd-linux-armv7 ./cmd/netflix-pbrd

package: build
	@mkdir -p dist/packages
	@VERSION='$(VERSION)' scripts/package.sh deb '$(VERSION)' dist/netflix-pbrd-linux-amd64 amd64 dist/packages
	@VERSION='$(VERSION)' scripts/package.sh deb '$(VERSION)' dist/netflix-pbrd-linux-arm64 arm64 dist/packages
	@VERSION='$(VERSION)' scripts/package.sh deb '$(VERSION)' dist/netflix-pbrd-linux-armv7 armhf dist/packages
	@VERSION='$(VERSION)' scripts/package.sh apk '$(VERSION)' dist/netflix-pbrd-linux-amd64 x86_64 dist/packages
	@VERSION='$(VERSION)' scripts/package.sh apk '$(VERSION)' dist/netflix-pbrd-linux-arm64 aarch64 dist/packages
	@VERSION='$(VERSION)' scripts/package.sh apk '$(VERSION)' dist/netflix-pbrd-linux-armv7 armv7 dist/packages
	@VERSION='$(VERSION)' scripts/package.sh ipk '$(VERSION)' dist/netflix-pbrd-linux-amd64 x86_64 dist/packages
	@VERSION='$(VERSION)' scripts/package.sh ipk '$(VERSION)' dist/netflix-pbrd-linux-arm64 aarch64_cortex-a53 dist/packages
	@VERSION='$(VERSION)' scripts/package.sh ipk '$(VERSION)' dist/netflix-pbrd-linux-armv7 arm_cortex-a7_neon-vfpv4 dist/packages

clean:
	rm -rf dist
