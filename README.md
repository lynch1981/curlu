# curlu

`curlu` is a focused HTTP/HTTPS command-line client written in Go. HTTPS
connections use [uTLS](https://github.com/refraction-networking/utls), while
the command-line interface and process behavior match the supported curl
workflow.

> [!WARNING]
> HTTPS certificate and hostname verification is always disabled in v1.
> Do not use curlu when authenticating the remote server matters.

## Supported command

```sh
curlu -i -H 'User-Agent:' -H 'Accept:' -H 'Host:' -sS \
  --connect-timeout 2.5 --max-time 10 \
  http://127.0.0.1:8080/health
```

Supported options:

- `-i`, `--include`
- `-H`, `--header` (repeatable)
- `-s`, `--silent`
- `-S`, `--show-error`
- `-v`, `--verbose`
- `--connect-timeout <seconds>`
- `-m`, `--max-time <seconds>`
- `--utls-hello <id>`
- `--utls-hello-list`
- `--utls-cipher-append <0xNNNN>` (repeatable)
- `--utls-info`
- `-k`, `--insecure` (accepted; verification is always disabled)
- `--http2-prior-knowledge` (accepted; ALPN still comes from the parrot)
- `-h`, `--help`
- `-V`, `--version`

Timeouts accept decimal seconds. A timeout of zero means no limit. Repeating a
timeout option uses its final value.

`-H 'Name:'` suppresses a header, including the normally generated `Host`,
`User-Agent`, and `Accept` headers. Header names are matched case-insensitively.

## uTLS controls

HTTPS uses the `HelloGolang` ClientHello by default. `--utls-hello` selects any
ClientHello ID reported by `--utls-hello-list`; matching is case-insensitive.
IDs are the uTLS constant names (`HelloChrome_120`), not a version number and
not names such as `Chrome-120`. The list includes every distinct
preset in the pinned uTLS release except `HelloCustom`, including Auto aliases
and experimental or upstream-marked incompatible presets. Those presets are
exposed intentionally and may fail to handshake with some servers.

```sh
curlu --utls-hello HelloChrome_133 https://example.com/
curlu --utls-hello-list
```

A selected parrot keeps its own ALPN. `HelloGolang` continues to advertise
`http/1.1` only. If the server selects `h2`, curlu performs the GET over
HTTP/2. If it selects `http/1.1` or no ALPN, the GET uses HTTP/1.1.

`--utls-cipher-append` appends one cipher-suite ID to the selected ClientHello.
The value must contain exactly four hexadecimal digits after a lowercase `0x`.
Repeating the option preserves order and duplicates, allowing exact wire-level
control. Arbitrary values are accepted; if a server selects a cipher that uTLS
cannot implement, the TLS handshake will fail.

`--utls-info` writes one machine-readable line to stderr after the final
ClientHello is built and before the handshake:

```text
EXPECTED_CIPHER_COUNT=17
```

The count includes appended values, duplicates, and SCSV entries, but excludes
GREASE cipher values. It is printed even with `--silent`. The Hello selector,
cipher append, and info options require an `https://` URL; using them with
`http://` is an invalid invocation.

Test::Nginx looks up a binary named `curl`. Point `PATH` at a `curl` that is
curlu (or `exec` curlu as `curl`). curlu accepts the argv Test::Nginx generates
(`-i -H -sS --http2-prior-knowledge --connect-timeout --max-time`, and a
single-token `--- curl_options` blob such as `--utls-hello HelloChrome_120`).

## Compatibility boundaries

curlu v1 performs one GET request to one explicit `http://` or `https://` URL.
`http://` uses HTTP/1.1. `https://` uses HTTP/2 when ALPN selects `h2` and
HTTP/1.1 otherwise. It connects directly and does not support proxy environment
variables, redirects, request bodies, URL globbing, configuration files, or
other protocols. HTTP 4xx and 5xx statuses are successful transfers, matching
curl without `--fail`.

Response data is written to stdout. `-i` includes the received status line and
headers (`HTTP/2 200` when the transfer used HTTP/2). Errors use
`curlu: (N) message` on stderr with the corresponding curl exit code. `-s`
suppresses diagnostics and `-S` restores them. `-v` writes a curl-style
connection and header trace to stderr (`*` info, `>` sent headers, `<`
received headers) even when `-s` is set. curlu does not implement a
progress meter.

## Build and test

uTLS v1.8.2 requires Go 1.24.0.

```sh
./build.sh
go test -race ./...
```

The build script requires Go 1.24.0 or newer on `PATH`, embeds the current Git
revision in the binary, and writes the executable to `./curlu`.

## Relevant exit codes

| Code | Meaning |
| ---: | --- |
| 0 | Transfer completed |
| 1 | Unsupported protocol |
| 2 | Invalid invocation |
| 3 | Malformed URL |
| 6 | Host resolution failed |
| 7 | Connection failed |
| 8 | Invalid HTTP response |
| 18 | Partial response body |
| 23 | Failed writing stdout |
| 28 | Timeout |
| 35 | TLS handshake failed |
| 52 | Empty server reply |
| 55 | Request send failed |
| 56 | Response receive failed |
