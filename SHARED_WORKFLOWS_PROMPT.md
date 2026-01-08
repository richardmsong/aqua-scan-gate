# Task: Create a Shared GitHub Workflows Repository

Create a repository called `shared-workflows` (or `.github`) with reusable GitHub Actions workflows for kubebuilder/Go projects that publish Docker images to GHCR.

## Context

This repo will be consumed by multiple downstream repositories (e.g., `richardmsong/jfrog-token-exchanger`, `richardmsong/aqua-scan-triggerer`) using GitHub's `workflow_call` mechanism. The goal is to have a single source of truth for CI/CD pipelines, making enhancements easy to propagate.

## Repository Structure

```
shared-workflows/
├── .github/
│   └── workflows/
│       ├── ci.yml                    # Reusable CI workflow (test, lint, build, docker)
│       ├── tag-release.yml           # Reusable release workflow (version branches, kustomize update)
│       ├── auto-pr.yml               # Reusable auto-PR for claude/* branches
│       ├── claude.yml                # Reusable Claude interaction on issues/PRs
│       ├── claude-code-review.yml    # Reusable Claude code review on PRs
│       ├── _test-ci.yml              # Internal: tests ci.yml against fixture on PRs
│       └── _test-release.yml         # Internal: tests tag-release.yml on PRs
├── test-fixtures/
│   └── kubebuilder-minimal/
│       ├── Makefile
│       ├── Dockerfile
│       ├── go.mod
│       ├── main.go
│       ├── main_test.go
│       └── config/
│           └── manager/
│               └── kustomization.yaml
└── README.md
```

## Workflow Specifications

### 1. `.github/workflows/ci.yml` - Reusable CI Workflow

This is the main CI workflow. It should:
- Use `on: workflow_call` with these inputs:
  - `working_directory` (string, default: '.')
  - `go_version_file` (string, default: 'go.mod')
  - `registry` (string, default: 'ghcr.io')
  - `image_name` (string, default: '' - falls back to `github.repository`)
  - `run_tests` (boolean, default: true)
  - `run_lint` (boolean, default: true)
  - `push_image` (boolean, default: true)
  - `golangci_lint_version` (string, default: 'v2.7.2')

Jobs:
1. **test**: Run `make test`, upload coverage artifact
2. **lint**: Run golangci-lint-action
3. **build**: Run `make build` (depends on test + lint)
4. **docker**: Build and push Docker image with smart tagging:
   - Always: `sha-<short>`
   - On branch push: branch name
   - On PR: `pr-<number>`
   - On tag `v*.*.*`: semver tags (`1.2.3`, `1.2`, `1` if not v0.x, `latest`)
   - On default branch: `latest`
   - Uses `make docker-buildx-ci` with `DOCKER_TAGS` and `DOCKER_PUSH` env vars

### 2. `.github/workflows/tag-release.yml` - Reusable Release Workflow

Triggers on `release: [published]` and `workflow_dispatch` (dry-run).

Inputs:
- `kustomize_path` (string, default: 'config/manager')
- `image_registry` (string, default: 'ghcr.io')

Steps:
1. Determine version from release tag or manual input
2. Validate semver format
3. Install kustomize via `make kustomize`
4. Update kustomization.yaml with new image tag
5. Commit version update to main (skip CI)
6. Force-push tag to include the version commit
7. Create/update minor version branch (e.g., `v1.2`)
8. Create/update major version branch (e.g., `v1`) - skip for v0.x
9. Write summary to `$GITHUB_STEP_SUMMARY`

Include dry-run support that shows what would happen without pushing.

### 3. `.github/workflows/auto-pr.yml` - Reusable Auto-PR Workflow

Triggers on push to `claude/**` branches.

Inputs:
- `use_app_token` (boolean, default: true) - whether to use Claude GitHub App token

Secrets (inherited):
- `CLAUDE_APP_ID`
- `CLAUDE_APP_PRIVATE_KEY`

Steps:
1. Generate Claude GitHub App token (if available)
2. Get commit title/body from HEAD
3. Create PR if one doesn't exist for the branch
4. Use app token so PR triggers other workflows (PRs from GITHUB_TOKEN don't trigger workflows)

### 4. `.github/workflows/claude.yml` - Reusable Claude Interaction

Triggers on:
- `issue_comment` (created) containing `@claude`
- `pull_request_review_comment` (created) containing `@claude`
- `pull_request_review` (submitted) containing `@claude`
- `issues` (opened, assigned) containing `@claude`

Inputs:
- `allowed_tools` (string, default: common Go/git tools)

Secrets (inherited):
- `CLAUDE_APP_ID`
- `CLAUDE_APP_PRIVATE_KEY`
- `CLAUDE_CODE_OAUTH_TOKEN`

Uses `anthropics/claude-code-action@v1`.

### 5. `.github/workflows/claude-code-review.yml` - Reusable Code Review

Triggers on `pull_request: [opened, synchronize]`.

Inputs:
- `allowed_tools` (string, default: gh PR tools only)

Secrets (inherited):
- `CLAUDE_APP_ID`
- `CLAUDE_APP_PRIVATE_KEY`
- `CLAUDE_CODE_OAUTH_TOKEN`

Prompt should instruct Claude to:
- Review code quality, bugs, performance, security, test coverage
- Use repo's CLAUDE.md for style guidance
- Leave review as PR comment via `gh pr comment`
- Condense previous verbose review comments
- Verify software versions before claiming they don't exist

### 6. `.github/workflows/_test-ci.yml` - Internal CI Test

Triggers on PRs that modify `ci.yml`.

```yaml
on:
  pull_request:
    paths: ['.github/workflows/ci.yml']

jobs:
  test-ci:
    uses: ./.github/workflows/ci.yml
    with:
      working_directory: test-fixtures/kubebuilder-minimal
      push_image: false
```

### 7. `.github/workflows/_test-release.yml` - Internal Release Test

Triggers on PRs that modify `tag-release.yml`. Runs dry-run mode against fixture.

## Test Fixture: `test-fixtures/kubebuilder-minimal/`

A minimal kubebuilder-style project that exercises the CI workflow.

### `Makefile`
```makefile
DOCKER_TAGS ?= test
DOCKER_PUSH ?=
IMG ?= ghcr.io/test/kubebuilder-minimal:latest

.PHONY: test build docker-build docker-buildx-ci kustomize

test:
	go test -race -coverprofile=cover.out ./...

build:
	CGO_ENABLED=0 go build -o bin/manager main.go

docker-build:
	docker build -t $(IMG) .

docker-buildx-ci:
	@echo "Building with tags: $(DOCKER_TAGS)"
	@echo "Push enabled: $(DOCKER_PUSH)"
	docker buildx create --use --name builder 2>/dev/null || true
	docker buildx build --platform linux/amd64,linux/arm64 \
		$(foreach tag,$(DOCKER_TAGS),--tag ghcr.io/test/kubebuilder-minimal:$(tag)) \
		$(if $(DOCKER_PUSH),--push,--load) \
		.

kustomize:
	@mkdir -p bin
	@echo "Kustomize would be installed here"
```

### `Dockerfile`
```dockerfile
FROM golang:1.23-alpine AS builder
WORKDIR /workspace
COPY go.mod go.sum ./
RUN go mod download
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o manager main.go

FROM gcr.io/distroless/static:nonroot
WORKDIR /
COPY --from=builder /workspace/manager .
USER 65532:65532
ENTRYPOINT ["/manager"]
```

### `go.mod`
```
module github.com/test/kubebuilder-minimal

go 1.23
```

### `main.go`
```go
package main

import "fmt"

func main() {
	fmt.Println(Greet("World"))
}

func Greet(name string) string {
	return fmt.Sprintf("Hello, %s!", name)
}
```

### `main_test.go`
```go
package main

import "testing"

func TestGreet(t *testing.T) {
	got := Greet("Test")
	want := "Hello, Test!"
	if got != want {
		t.Errorf("Greet() = %q, want %q", got, want)
	}
}
```

### `config/manager/kustomization.yaml`
```yaml
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources: []
images:
- name: controller
  newName: ghcr.io/test/kubebuilder-minimal
  newTag: latest
```

## README.md

Write a comprehensive README that includes:
1. Overview of what this repo provides
2. Quick start example showing how to consume workflows
3. Full reference for each workflow's inputs/secrets
4. SDLC explanation (how to test changes, versioning strategy)
5. Example caller workflows for each reusable workflow

### Example Caller Workflow (for README)
```yaml
# In downstream repo: .github/workflows/ci.yml
name: CI
on:
  push:
    branches: [main, master]
    tags: ['v*.*.*']
  pull_request:
    branches: [main, master]

permissions:
  contents: read
  packages: write

jobs:
  ci:
    uses: richardmsong/shared-workflows/.github/workflows/ci.yml@main
    # Or pin to version: @v1
```

## Git Setup

1. Initialize the repository
2. Create initial commit with all files
3. Push to `main` branch
4. Create a `v1` tag for stable consumers

## Important Notes

- All reusable workflows must use `on: workflow_call`
- Secrets cannot be passed directly to reusable workflows - they must use `secrets: inherit` or be declared
- The test workflows (prefixed with `_`) are internal and test the reusable workflows against the fixture
- Use `@main` for canary/early-adopter repos, `@v1` for stable repos
