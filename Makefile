VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64

.PHONY: all jar cli dist test vet clean install

all: jar cli

jar:
	cd extension && gradle jar -q
	@mkdir -p dist && cp extension/build/libs/hiccup-burp.jar dist/

cli:
	@mkdir -p dist
	go build -ldflags "$(LDFLAGS)" -o dist/hiccup ./cmd/hiccup

dist: jar
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
		echo "build $$os/$$arch"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" \
			-o dist/hiccup-$$os-$$arch$$ext ./cmd/hiccup || exit 1; \
	done

test:
	go test ./...

vet:
	go vet ./...

# Copies the extension where `hiccup burp start` looks for it by default.
install: jar cli
	@mkdir -p $${HICCUP_HOME:-$$HOME/.hiccup}
	cp dist/hiccup-burp.jar $${HICCUP_HOME:-$$HOME/.hiccup}/

clean:
	rm -rf dist extension/build extension/.gradle
