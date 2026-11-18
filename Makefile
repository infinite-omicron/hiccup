VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
# Archive names drop the tag's leading "v": hiccup_1.2.3_linux_amd64.tar.gz
FILEVER := $(patsubst v%,%,$(VERSION))
PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64

.PHONY: all jar cli dist release test vet clean install

all: jar cli

jar:
	cd extension && ./gradlew jar -q -PhiccupVersion=$(VERSION)
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

# Release assets in dist/release: one archive per platform (each holding a
# binary named hiccup or hiccup.exe, hiccup-burp.jar and the README), the
# extension jar on its own, and SHA-256 checksums.
release: dist
	@rm -rf dist/release && mkdir -p dist/release
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; name=hiccup_$(FILEVER)_$${os}_$${arch}; \
		stage=dist/stage/$$name; rm -rf $$stage; mkdir -p $$stage; cp README.md dist/hiccup-burp.jar $$stage/; \
		if [ $$os = windows ]; then \
			cp dist/hiccup-$$os-$$arch.exe $$stage/hiccup.exe; \
			(cd dist/stage && zip -qr ../release/$$name.zip $$name); \
		else \
			cp dist/hiccup-$$os-$$arch $$stage/hiccup; \
			tar -C dist/stage -czf dist/release/$$name.tar.gz $$name; \
		fi; \
	done
	@cp dist/hiccup-burp.jar dist/release/hiccup-burp_$(FILEVER).jar
	@rm -rf dist/stage
	@cd dist/release && (command -v sha256sum >/dev/null && sha256sum * || shasum -a 256 *) > ../checksums.txt && mv ../checksums.txt .
	@ls -1 dist/release

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
