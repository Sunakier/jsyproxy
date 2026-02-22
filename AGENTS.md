# AGENTS.md — jsyproxy Agent Guide

Operational guide for coding agents in this repository.

## Project Snapshot
- Language: Go
- Module: `jsyproxy`
- Go version: `1.21` (see `go.mod`)
- HTTP framework: Gin (`github.com/gin-gonic/gin`)
- Entry file: `main.go`

Main directories:
- `config/` env + startup config
- `handlers/` HTTP/API handlers
- `middleware/` auth middleware
- `store/` state/cache/persistence
- `utils/` helper utilities
- `static/` embedded admin assets

## Command Sources
Use these files as command truth:
- `README.md`
- `.github/workflows/go-ci-release.yml`
- `.github/workflows/docker-build.yml`

This repo has no `Makefile`, `Taskfile`, npm scripts, or JS/TS toolchain.

## Setup and Run
Install deps:
```bash
go mod download
```
Run service:
```bash
go run main.go
```
Required env var:
- `ADMIN_PASSWORD` (startup exits if empty)

Common optional env vars:
- `PORT` (default `3000`)
- `DATA_FILE` (default `data/state.json`)
- `DEFAULT_REFRESH_INTERVAL` (default `10m`)
- `ACCESS_KEYS` (comma-separated bootstrap keys)

## Build / Check / Test
Build all packages:
```bash
go build ./...
```
CI-style release binary build:
```bash
go build -trimpath -ldflags "-s -w" -o dist/jsyproxy .
```
Static analysis (lint-like):
```bash
go vet ./...
```
Run all tests:
```bash
go test ./...
```
Run a single test (when tests exist):
```bash
go test -run TestName ./...
go test -run '^TestName$' ./handlers
go test -v -run '^TestName$' ./store
```

Current repo status:
- No `*_test.go` files exist right now.
- `go test ./...` returns `[no test files]`.
- No `golangci-lint` config is present.

## Formatting
Check formatting:
```bash
gofmt -l .
```
Apply formatting:
```bash
gofmt -w .
```
If you edit Go files, run gofmt before finishing.

## Docker
Compose:
```bash
docker-compose up -d
```
Local image build:
```bash
docker build -t jsyproxy .
```

## Code Style Rules (from existing code)

### Imports
- Group imports: stdlib → internal (`jsyproxy/...`) → external.
- Keep one blank line between groups.
- Alias only when needed (e.g. `staticfiles "jsyproxy/static"`).

### Naming
- Exported symbols: PascalCase (`SubscribeHandler`, `AdminStatus`).
- Internal symbols: camelCase (`refreshMutex`, `appendClientLog`).
- Receivers are short (`h`, `s`, `c`).

### Types and JSON
- Define request payload structs for handler inputs.
- Use explicit JSON tags.
- Use snake_case JSON keys (`upstream_id`, `api_endpoint`).
- Keep response shape consistent (`{"ok": true}`, `{"error": "..."}`).

### Error handling
- Check errors immediately (`if err != nil`).
- Wrap propagated errors with `%w` for context.
- Handler failures return JSON + proper HTTP status.
- Startup fatal logging is acceptable for unrecoverable config errors.
- Do not silently ignore operational errors.

### HTTP conventions
- Validate early; return early.
- Use `c.ShouldBindJSON(&req)` for JSON bodies.
- Status code mapping used in this codebase:
  - 200 success
  - 400 bad request
  - 401 unauthorized
  - 403 forbidden
  - 404 not found
  - 500 internal error
  - 502 upstream error

### Concurrency and logging
- `store.State` uses `sync.RWMutex`; preserve lock discipline.
- Read paths: `RLock/RUnlock`; write paths: `Lock/Unlock`.
- Use `log.Printf` with useful context (upstream id, reason, status).
- Never log secrets (passwords, tokens, auth headers).

## Agent Validation Checklist
For code changes, run in order:
1. `gofmt -w .`
2. `go vet ./...`
3. `go test ./...`
4. `go build ./...`

If runtime behavior changes, run the app and sanity-check key endpoints.

## Cursor / Copilot Rules
Checked and currently absent:
- `.cursor/rules/`
- `.cursorrules`
- `.github/copilot-instructions.md`

If these files are added later, merge their instructions into this guide.
