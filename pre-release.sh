#!/usr/bin/env bash
#
# pre-release.sh - Local pre-release verification gate.
#
# Runs the full quality suite against the working tree: formatting, vetting,
# linting, tests (with race detection and coverage) and cross-platform builds
# for Linux, macOS and Windows.
#
# Invoked automatically by release.sh, but also useful on its own:
#
#   ./pre-release.sh
#
# Environment variables:
#   SKIP_LINT=1       Skip golangci-lint (not recommended)
#   SKIP_RACE=1       Skip the race detector (e.g. where cgo is unavailable)
#   AUTO_INSTALL=1    Install golangci-lint automatically if it is missing
#   COVER_PROFILE     Coverage output file (default: coverage.out)
#   MIN_COVERAGE      Minimum total coverage %, e.g. 40 (default: unset/no gate)
#
# Exits non-zero on the first failure, so callers can gate on it.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

COVER_PROFILE="${COVER_PROFILE:-coverage.out}"
# Track the latest stable golangci-lint by default. Pin GOLANGCI_VERSION to a
# specific tag (e.g. v2.1.6) only if you need reproducibility.
GOLANGCI_VERSION="${GOLANGCI_VERSION:-latest}"

# Colours, only when attached to a terminal.
if [[ -t 1 ]]; then
  RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
  BLUE=$'\033[0;34m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
  RED=""; GREEN=""; YELLOW=""; BLUE=""; BOLD=""; RESET=""
fi

STEP=0
step()  { STEP=$((STEP + 1)); printf '\n%s==> [%d] %s%s\n' "${BLUE}${BOLD}" "$STEP" "$1" "$RESET"; }
ok()    { printf '%s    ✓ %s%s\n' "$GREEN" "$1" "$RESET"; }
warn()  { printf '%s    ! %s%s\n' "$YELLOW" "$1" "$RESET"; }
fail()  { printf '\n%s    ✗ %s%s\n' "${RED}${BOLD}" "$1" "$RESET" >&2; exit 1; }

printf '%s%s\n' "${BOLD}" "vantage pre-release verification${RESET}"
printf '    repo: %s\n' "$REPO_ROOT"

# ---------------------------------------------------------------------------
step "Toolchain"
# ---------------------------------------------------------------------------
command -v go >/dev/null 2>&1 || fail "Go toolchain not found on PATH."
ok "$(go version)"

# ---------------------------------------------------------------------------
step "Module tidiness"
# ---------------------------------------------------------------------------
# go.mod/go.sum must already be tidy; releasing an untidy module breaks
# reproducible builds for consumers.
cp go.mod go.mod.prerelease.bak
cp go.sum go.sum.prerelease.bak
restore_mod() {
  mv -f go.mod.prerelease.bak go.mod 2>/dev/null || true
  mv -f go.sum.prerelease.bak go.sum 2>/dev/null || true
}
trap restore_mod EXIT

go mod tidy
if ! diff -q go.mod go.mod.prerelease.bak >/dev/null 2>&1 ||
   ! diff -q go.sum go.sum.prerelease.bak >/dev/null 2>&1; then
  restore_mod
  trap - EXIT
  fail "go.mod/go.sum are not tidy. Run 'go mod tidy' and commit the result."
fi
restore_mod
trap - EXIT
ok "go.mod and go.sum are tidy"

go mod verify >/dev/null || fail "Module dependency verification failed."
ok "Module dependencies verified"

# ---------------------------------------------------------------------------
step "Formatting"
# ---------------------------------------------------------------------------
UNFORMATTED="$(gofmt -l . | grep -v '^vendor/' || true)"
if [[ -n "$UNFORMATTED" ]]; then
  printf '%s\n' "$UNFORMATTED" >&2
  fail "The files above are not gofmt-formatted. Run 'gofmt -w .'."
fi
ok "All files are gofmt-formatted"

# ---------------------------------------------------------------------------
step "go vet"
# ---------------------------------------------------------------------------
go vet ./... || fail "go vet reported problems."
ok "go vet is clean"

# ---------------------------------------------------------------------------
step "User-visible prose"
# ---------------------------------------------------------------------------
# Advisory text is this library's product. It is read in a terminal, embedded
# in Trawl's interface and rendered into reports, so its punctuation has to
# survive all three. Checks string literals and user documentation only, never
# comments.
go run ./tools/prosecheck || fail "Em dashes found in user-visible text. Run 'go run ./tools/prosecheck --fix'."
ok "No em dashes in user-visible text"

# ---------------------------------------------------------------------------
step "golangci-lint"
# ---------------------------------------------------------------------------
if [[ "${SKIP_LINT:-0}" == "1" ]]; then
  warn "SKIP_LINT=1 set; skipping lint (not recommended for a release)"
elif command -v golangci-lint >/dev/null 2>&1; then
  ok "$(golangci-lint --version)"
  golangci-lint run ./... || fail "golangci-lint reported problems."
  ok "golangci-lint is clean"
elif [[ "${AUTO_INSTALL:-0}" == "1" ]]; then
  warn "golangci-lint not found; installing ${GOLANGCI_VERSION}..."
  go install "github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_VERSION}" ||
    fail "Failed to install golangci-lint."
  "$(go env GOPATH)/bin/golangci-lint" run ./... || fail "golangci-lint reported problems."
  ok "golangci-lint is clean"
else
  fail "golangci-lint not found. Install it, re-run with AUTO_INSTALL=1, or set SKIP_LINT=1.
      brew install golangci-lint
      # or
      go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@${GOLANGCI_VERSION}"
fi

# ---------------------------------------------------------------------------
step "Tests"
# ---------------------------------------------------------------------------
TEST_FLAGS=(-cover -coverprofile="$COVER_PROFILE" -covermode=atomic)
if [[ "${SKIP_RACE:-0}" == "1" ]]; then
  warn "SKIP_RACE=1 set; running without the race detector"
else
  TEST_FLAGS+=(-race)
fi

go test ./... "${TEST_FLAGS[@]}" || fail "Tests failed."
ok "All tests passed"

TOTAL_COVERAGE="$(go tool cover -func="$COVER_PROFILE" | awk '/^total:/ {print $3}')"
ok "Total coverage: ${TOTAL_COVERAGE}"

if [[ -n "${MIN_COVERAGE:-}" ]]; then
  COVERAGE_NUM="${TOTAL_COVERAGE%\%}"
  if awk -v c="$COVERAGE_NUM" -v m="$MIN_COVERAGE" 'BEGIN { exit !(c < m) }'; then
    fail "Coverage ${TOTAL_COVERAGE} is below the required minimum of ${MIN_COVERAGE}%."
  fi
  ok "Coverage meets the ${MIN_COVERAGE}% minimum"
fi

# ---------------------------------------------------------------------------
step "Cross-platform builds"
# ---------------------------------------------------------------------------
# vantage supports Linux, macOS and Windows; resolver discovery is
# build-tagged per platform, so every target must be compiled.
PLATFORMS=(
  "linux/amd64"
  "linux/arm64"
  "darwin/amd64"
  "darwin/arm64"
  "windows/amd64"
  "windows/arm64"
)

BUILD_TMP="$(mktemp -d)"
trap 'rm -rf "$BUILD_TMP"' EXIT

for platform in "${PLATFORMS[@]}"; do
  GOOS="${platform%%/*}"
  GOARCH="${platform##*/}"
  output="$BUILD_TMP/vantage-${GOOS}-${GOARCH}"
  [[ "$GOOS" == "windows" ]] && output+=".exe"

  # Compile every package (catches build-tagged code that the binary alone may
  # not pull in), then link the CLI itself.
  if ! CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build ./...; then
    fail "Build failed for ${GOOS}/${GOARCH} (packages)."
  fi
  if ! CGO_ENABLED=0 GOOS="$GOOS" GOARCH="$GOARCH" go build -o "$output" .; then
    fail "Build failed for ${GOOS}/${GOARCH} (binary)."
  fi
  ok "build ${GOOS}/${GOARCH}"
done

# ---------------------------------------------------------------------------
step "Smoke test"
# ---------------------------------------------------------------------------
# Confirm the binary actually starts and the command surface is intact. This
# performs no network I/O.
SMOKE_BIN="$BUILD_TMP/vantage-smoke"
go build -o "$SMOKE_BIN" . || fail "Failed to build the host binary."

HELP_OUTPUT="$("$SMOKE_BIN" --help 2>&1)" || fail "'vantage --help' exited non-zero."
for cmd in audit spf dkim dmarc dmarc-report mtasts dnssec nssec \
           smtp-dane https-dane ssh-dane caa ptr dnsbl public-suffix \
           catalogue explain version; do
  grep -qE "^[[:space:]]+${cmd}[[:space:]]" <<<"$HELP_OUTPUT" ||
    fail "Command '${cmd}' is missing from the CLI help output."
done
ok "All commands are registered"

for flag in --resolver --query-timeout --timeout --query-rate --format --findings \
            --fail-on --severity; do
  grep -q -- "$flag" <<<"$HELP_OUTPUT" || fail "Global flag '${flag}' is missing."
done
ok "Global flags are present"

# Version metadata must resolve even without release-time ldflags.
"$SMOKE_BIN" version >/dev/null || fail "'vantage version' failed."
"$SMOKE_BIN" --version >/dev/null || fail "'vantage --version' failed."
ok "Version information is available"

# Public Suffix validation needs no network, so it is a safe end-to-end check.
"$SMOKE_BIN" public-suffix com >/dev/null || fail "'public-suffix com' failed."

# The finding catalogue is offline data, so it is fully checkable here. These
# assertions guard the contract that findings are self-describing: an ID that
# resolves to no guidance is worse than useless to whoever has to act on it.
"$SMOKE_BIN" catalogue >/dev/null || fail "'vantage catalogue' failed."
"$SMOKE_BIN" explain SURF-SPF-004 >/dev/null || fail "'vantage explain' failed."
# Captured rather than piped into grep -q. Under `set -o pipefail`, grep -q
# exits at the first match and the still-writing producer takes SIGPIPE, so the
# pipeline reports 141 and the check fails despite having found what it wanted.
CATALOGUE_JSON="$("$SMOKE_BIN" catalogue -o json)" ||
  fail "'vantage catalogue -o json' failed."
grep -q '"remediation"' <<<"$CATALOGUE_JSON" ||
  fail "Catalogue JSON is missing remediation guidance."
if "$SMOKE_BIN" explain SURF-NOPE-001 >/dev/null 2>&1; then
  fail "'explain' accepted an unknown finding ID."
fi

# The audit registry is offline metadata. Every check must describe itself, and
# a misspelt check name must be rejected rather than silently skipped: a run
# that quietly assesses nothing is the most dangerous output this tool could
# produce.
CHECK_LIST="$("$SMOKE_BIN" audit --list-checks)" || fail "'audit --list-checks' failed."
for check in spf dmarc dkim dnssec nssec caa mtasts mx ptr; do
  grep -qE "^${check}[[:space:]]" <<<"$CHECK_LIST" ||
    fail "Check '${check}' is missing from the audit registry."
done
if "$SMOKE_BIN" audit example.com --checks not-a-check >/dev/null 2>&1; then
  fail "'audit' accepted an unknown check name."
fi
if "$SMOKE_BIN" audit --profile not-a-profile example.com >/dev/null 2>&1; then
  fail "'audit' accepted an unknown profile."
fi
if "$SMOKE_BIN" audit >/dev/null 2>&1; then
  fail "'audit' ran without any target."
fi
ok "Offline end-to-end check passed"

# ---------------------------------------------------------------------------
step "Release configuration"
# ---------------------------------------------------------------------------
if [[ -f .goreleaser.yml || -f .goreleaser.yaml ]]; then
  if command -v goreleaser >/dev/null 2>&1; then
    goreleaser check || fail "GoReleaser configuration is invalid."
    ok "GoReleaser configuration is valid"
  else
    warn "goreleaser not installed; skipping config validation"
  fi
else
  warn "No GoReleaser configuration found"
fi

printf '\n%s%s%s\n\n' "${GREEN}${BOLD}" "✓ Pre-release verification passed." "$RESET"
