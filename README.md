# curlu

License: BSD-3-Clause — see LICENSE file.

curlu is a small HTTP/HTTPS GET client written in Go. Its command-line
interface matches the curl workflow used by Test::Nginx. It has two
independent capabilities: it can customize the TLS ClientHello via uTLS
for a stable JA4 fingerprint, and it can craft the TCP SYN for a JA4T
fingerprint. Go 1.24.0 and
[uTLS](https://github.com/refraction-networking/utls) v1.8.2 are pinned so
those fingerprints stay reproducible.

> [!WARNING]
> HTTPS certificate and hostname verification is always disabled in v1.
> Do not use curlu when authenticating the remote server matters.

## Example

```sh
curlu -i -H 'User-Agent:' -H 'Accept:' -H 'Host:' -sS \
  --connect-timeout 2.5 --max-time 10 \
  http://127.0.0.1:8080/health
```

This sends one GET, prints the response headers and body, and omits the
generated `User-Agent`, `Accept`, and `Host` headers.

Test::Nginx looks up a binary named `curl`. Pointing `PATH` at the repo root
is enough. curlu accepts the argv Test::Nginx generates (`-i -H -sS
--http2-prior-knowledge --connect-timeout --max-time`, and a single-token
`--- curl_options` blob such as `--utls-hello HelloChrome_120`).

## Options

- `-i`, `--include` — Include response headers in stdout
- `-H`, `--header` — Add, replace, or suppress a request header (repeatable)
- `-s`, `--silent` — Suppress error diagnostics
- `-S`, `--show-error` — Show errors when used with `--silent`
- `-v`, `--verbose` — Show connection and header trace on stderr
- `--connect-timeout <secs>` — Limit DNS, TCP, and TLS connection time
- `-m`, `--max-time <secs>` — Limit the complete transfer time
- `--resolve <host:port:addr>` — Map host+port to address (repeatable)
- `--utls-hello <id>` — Select a uTLS ClientHello ID (`HelloChrome_120`)
- `--utls-hello-list` — List supported uTLS ClientHello IDs
- `--utls-cipher-append <0xNNNN>` — Append a cipher ID (repeatable)
- `--utls-alpn-hex <hex>` — Set the first ALPN protocol from even-length hex
- `--utls-alpn-none` — Omit the ALPN extension
- `--utls-info` — Print `EXPECTED_CIPHER_COUNT` to stderr
- `--ja4t <fingerprint>` — Craft the TCP SYN to match a JA4T fingerprint (HTTP only; run via `./curl` as root)
- `-k`, `--insecure` — Accepted; verification is always disabled
- `--http2-prior-knowledge` — Accepted; parrot ALPN still applies unless overridden
- `-h`, `--help` — Show this help
- `-V`, `--version` — Show version information

Timeouts accept decimal seconds. `0` means no limit. The last value of a
repeated timeout option wins.

`--resolve` maps a URL host and port to one or more numeric addresses. It
does not change `Host` or TLS SNI. The port must match the URL (`80` or `443`
when omitted). `*` matches any host for that port, and is used only when no
specific host matches. A leading `+` is accepted. `-host:port` removes an
earlier mapping.

```sh
curlu --resolve example.com:443:127.0.0.1 https://example.com/
```

`-H 'Name:'` suppresses a header, including the normally generated `Host`,
`User-Agent`, and `Accept` headers. Header names are matched case-insensitively.

## uTLS

HTTPS uses `HelloGolang` by default. `--utls-hello` selects an ID from
`--utls-hello-list` (case-insensitive uTLS names such as `HelloChrome_120`).
The list includes every preset except `HelloCustom`. Experimental and
incompatible presets are included and may fail to handshake.

```sh
curlu --utls-hello HelloChrome_133 https://example.com/
curlu --utls-hello-list
```

A parrot keeps its ALPN (`HelloGolang` advertises `http/1.1` only).
`--utls-alpn-hex` replaces the first protocol from even-length hex;
`--utls-alpn-none` omits ALPN. If the server selects `h2`, the GET uses
HTTP/2; otherwise it uses HTTP/1.1.

`--utls-cipher-append 0xNNNN` appends a cipher ID. Repeating it keeps
order and duplicates. If the server selects a cipher uTLS cannot
implement, the handshake fails.

`--utls-info` prints `EXPECTED_CIPHER_COUNT=N` to stderr before the
handshake, even with `--silent`. The count includes appended, duplicate,
and SCSV values, but not GREASE.

These flags require `https://`.

## JA4T

`--ja4t` crafts the TCP SYN so a listener sees the given JA4T fingerprint
(`window_options_mss_wscale`). HTTP only. Combining it with `--utls-*` or an
`https://` URL is invalid. IPv6 is not supported.

```sh
sudo ./curl --ja4t 64240_2-4-8-1-3_1460_7 http://127.0.0.1:8080/t
```

Crafting a SYN needs a raw socket, and the kernel would RST the SYN-ACK.
The repo ships a `curl` wrapper (not a symlink) for that path. Without
`--ja4t` the wrapper runs `curlu` unchanged. With `--ja4t` it needs root,
`ip`, and `nft`. `./curlu --ja4t` is unsupported.

## Limits

- One GET to one explicit `http://` or `https://` URL.
- No proxies, redirects, request bodies, URL globbing, config files, or
  other protocols.

## Build and test

Go 1.24.0 and uTLS v1.8.2 are pinned so JA4 ClientHello fingerprints stay
reproducible. Bumping either can change `HelloGolang` and parrot JA4 values
and must be paired with catalog and expected-fingerprint updates.

`./build.sh` sets `GOTOOLCHAIN=go1.24.0` from the `go` line in `go.mod` and
refuses any other compiler. Tests need the same toolchain:

```sh
./build.sh
GOTOOLCHAIN=go1.24.0 go test -race ./...
```

The build embeds the current Git revision and writes `./curlu`. The `./curl`
wrapper is a checked-in script next to it.

## Output

Response data goes to stdout. `-i` includes the status line and headers
(`HTTP/2 200` when the transfer used HTTP/2).

Errors are `curlu: (N) message` on stderr, with the matching curl exit
code. HTTP 4xx and 5xx are successful transfers, matching curl without
`--fail`.

## Exit codes

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
