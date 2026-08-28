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
- `--connect-timeout <seconds>`
- `-m`, `--max-time <seconds>`
- `-h`, `--help`
- `-V`, `--version`

Timeouts accept decimal seconds. A timeout of zero means no limit. Repeating a
timeout option uses its final value.

`-H 'Name:'` suppresses a header, including the normally generated `Host`,
`User-Agent`, and `Accept` headers. Header names are matched case-insensitively.

## Compatibility boundaries

curlu v1 performs one HTTP/1.1 GET request to one explicit `http://` or
`https://` URL. It connects directly and does not support proxy environment
variables, redirects, request bodies, URL globbing, configuration files,
HTTP/2, or other protocols. HTTP 4xx and 5xx statuses are successful transfers,
matching curl without `--fail`.

Response data is written to stdout. `-i` includes the received status line and
headers. Errors use `curlu: (N) message` on stderr with the corresponding curl
exit code. `-s` suppresses diagnostics and `-S` restores them. curlu does not
implement a progress meter.

## Build and test

uTLS v1.8.2 requires Go 1.24.

```sh
./build.sh
go test -race ./...
```

The build script requires Go 1.24 or newer on `PATH`, embeds the current Git
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
