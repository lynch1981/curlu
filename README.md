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
- `--ja4t-retransmit <ms-ms-…>` — SYN retry delays in milliseconds (requires `--ja4t`)
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

HTTPS uses the `HelloGolang` ClientHello by default. `--utls-hello` selects
any ID from `--utls-hello-list`. Matching is case-insensitive. IDs are uTLS
constant names (`HelloChrome_120`), not version numbers and not names such as
`Chrome-120`.

The list includes every distinct preset in the pinned uTLS release except
`HelloCustom`, including Auto aliases and experimental or upstream-marked
incompatible presets. Those presets are exposed on purpose and may fail to
handshake with some servers.

```sh
curlu --utls-hello HelloChrome_133 https://example.com/
curlu --utls-hello-list
```

A selected parrot keeps its own ALPN. `HelloGolang` advertises `http/1.1`
only. `--utls-alpn-hex` replaces the first advertised protocol with the
decoded bytes (even-length hex, so values with spaces survive Test::Nginx
`--- curl_options`). Remaining parrot protocols are kept, so Chrome stays
`[decoded, "http/1.1"]`. `--utls-alpn-none` omits the ALPN extension.

If the server selects `h2`, the GET uses HTTP/2. If it selects `http/1.1` or
no ALPN, the GET uses HTTP/1.1.

`--utls-cipher-append` appends one cipher-suite ID to the selected
ClientHello. The value must be four hexadecimal digits after a lowercase
`0x`. Repeating the option keeps order and duplicates. Arbitrary values are
accepted; if a server selects a cipher that uTLS cannot implement, the
handshake fails.

`--utls-info` writes one line to stderr after the ClientHello is built and
before the handshake:

```text
EXPECTED_CIPHER_COUNT=17
```

The count includes appended values, duplicates, and SCSV entries, but
excludes GREASE cipher values. It is printed even with `--silent`.

`--utls-hello`, `--utls-cipher-append`, `--utls-alpn-hex`, `--utls-alpn-none`,
and `--utls-info` require an `https://` URL.

## JA4T

`--ja4t` crafts the TCP SYN so a listener sees the given JA4T fingerprint
(`window_options_mss_wscale`). HTTP only. Combining it with `--utls-*` or an
`https://` URL is invalid. IPv6 is not supported.

```sh
sudo ./curl --ja4t 64240_2-4-8-1-3_1460_7 http://127.0.0.1:8080/t
sudo ./curl --ja4t 65535_2-1-3-1-1-8-4-0-0_1460_6 \
  --ja4t-retransmit 1000-2000-4000 http://127.0.0.1:8080/t
```

`--ja4t-retransmit` is millisecond delays between SYN retries while waiting
for SYN-ACK. It is not part of the JA4T string. A server that answers the
first SYN never sees the retries.

Crafting a SYN needs a raw socket, and the kernel would RST the SYN-ACK.
The repo ships a `curl` wrapper (not a symlink) for that path. Without
`--ja4t` the wrapper runs `curlu` unchanged. With `--ja4t` it needs root,
`ip`, and `nft`. `./curlu --ja4t` is unsupported.

Test::Nginx looks up a binary named `curl`. Pointing `PATH` at the repo root
is enough. curlu accepts the argv Test::Nginx generates (`-i -H -sS
--http2-prior-knowledge --connect-timeout --max-time`, and a single-token
`--- curl_options` blob such as `--utls-hello HelloChrome_120`).

## Limits

- One GET to one explicit `http://` or `https://` URL.
- `http://` uses HTTP/1.1. With `--ja4t` the SYN is crafted in userspace;
  otherwise the kernel TCP stack is used.
- `https://` uses HTTP/2 when ALPN selects `h2`, and HTTP/1.1 otherwise.
- No proxies, redirects, request bodies, URL globbing, config files, or
  other protocols.
- HTTP 4xx and 5xx are successful transfers, matching curl without `--fail`.
- Response data goes to stdout. `-i` includes the status line and headers
  (`HTTP/2 200` when the transfer used HTTP/2).
- Errors are `curlu: (N) message` on stderr, with the matching curl exit
  code. `-s` hides diagnostics; `-S` shows them again.
- `-v` writes a curl-style connection and header trace to stderr (`*` info,
  `>` sent headers, `<` received headers), even when `-s` is set.
- There is no progress meter.

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
