VERSION ?= dev

.DEFAULT_GOAL := build

test:
	go fmt ./...
	go vet ./...
	go clean -testcache && go test -cover ./...
.PHONY:test

# golangci-lint is not part of `test`, since it is not always installed. CI runs
# it on every push.
lint:
	golangci-lint run ./...
.PHONY:lint

# What the standard library and the dependencies are known to be wrong about,
# and whether this code reaches any of it. CI runs it on every push.
vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
.PHONY:vuln

# the fixtures are only the cases somebody thought to write down; this puts the
# same questions to every certificate in the machine's trust store
corpus:
	./scripts/corpus-check.sh
.PHONY:corpus

build: test
	go build -ldflags "-X main.Version=${VERSION}" -mod vendor
.PHONY:build

install: test
	go install -ldflags "-X main.Version=${VERSION}" -mod vendor
.PHONY:install

# Reusable variables
GORELEASER ?= goreleaser
GITHUB_TOKEN ?= $(shell echo $$GITHUB_TOKEN)

release: release-linux-amd64 release-linux-arm64 release-mac release-windows-amd64 release-windows-arm64
	@echo "✅ All artifacts uploaded to the same GitHub release."

# Nothing here needs cgo, so every platform cross-compiles on whatever machine
# runs this, with no C toolchain and no container.
release-mac:
	env -u GITLAB_TOKEN -u GITEA_TOKEN $(GORELEASER) release --clean --config .goreleaser/.goreleaser.darwin.yml

release-linux-amd64:
	env -u GITLAB_TOKEN -u GITEA_TOKEN $(GORELEASER) release --clean --config .goreleaser/.goreleaser.linux-amd64.yml

release-linux-arm64:
	env -u GITLAB_TOKEN -u GITEA_TOKEN $(GORELEASER) release --clean --config .goreleaser/.goreleaser.linux-arm64.yml

release-windows-amd64:
	env -u GITLAB_TOKEN -u GITEA_TOKEN $(GORELEASER) release --clean --config .goreleaser/.goreleaser.windows-amd64.yml

release-windows-arm64:
	env -u GITLAB_TOKEN -u GITEA_TOKEN $(GORELEASER) release --clean --config .goreleaser/.goreleaser.windows-arm64.yml

ifndef GITHUB_TOKEN
$(error GITHUB_TOKEN is not set. Run: export GITHUB_TOKEN=<your PAT with repo scope>)
endif
