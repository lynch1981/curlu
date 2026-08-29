#!/usr/bin/env bash

set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")"

if ! command -v go >/dev/null 2>&1; then
  printf 'Error: Go is required to build curlu. Install go1.24.0 from https://go.dev/dl/\n' >&2
  exit 1
fi

toolchain="$(awk '/^toolchain[[:space:]]+/ { print $2; exit }' go.mod)"
if [[ -z "${toolchain}" ]]; then
  go_line="$(awk '/^go[[:space:]]+/ { print $2; exit }' go.mod)"
  if [[ -z "${go_line}" ]]; then
    printf 'Error: go.mod is missing a go line\n' >&2
    exit 1
  fi
  toolchain="go${go_line}"
fi

export GOTOOLCHAIN="${toolchain}"

go_version="$(go env GOVERSION)"
if [[ "${go_version}" != "${toolchain}" ]]; then
  printf 'Error: JA4 fingerprints require %s exactly; found %s\n' "${toolchain}" "${go_version}" >&2
  exit 1
fi

version="$(git describe --tags --always --dirty 2>/dev/null || printf 'dev')"

go build \
  -trimpath \
  -ldflags "-X main.version=${version}" \
  -o curlu \
  ./cmd/curlu

rm -f curl
ln -s curlu curl

printf 'Built curlu (%s) and symlink curl -> curlu\n' "${version}"
