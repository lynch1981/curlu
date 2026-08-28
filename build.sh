#!/usr/bin/env bash

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if ! command -v go >/dev/null 2>&1; then
  printf 'Error: Go 1.24.0 or newer is required. Install it from https://go.dev/dl/\n' >&2
  exit 1
fi

go_version="$(go env GOVERSION)"
if [[ ! "${go_version}" =~ ^go([0-9]+)\.([0-9]+) ]]; then
  printf 'Error: unable to determine the Go version from %s\n' "${go_version}" >&2
  exit 1
fi

go_major="${BASH_REMATCH[1]}"
go_minor="${BASH_REMATCH[2]}"
if ((go_major < 1 || (go_major == 1 && go_minor < 24))); then
  printf 'Error: Go 1.24.0 or newer is required; found %s\n' "${go_version}" >&2
  exit 1
fi

version="$(git describe --tags --always --dirty 2>/dev/null || printf 'dev')"

go build \
  -trimpath \
  -ldflags "-X main.version=${version}" \
  -o curlu \
  ./cmd/curlu

printf 'Built curlu (%s)\n' "${version}"
