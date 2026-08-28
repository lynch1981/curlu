package curlu

import (
	"fmt"
	"io"
	"strings"
)

const helpText = `Usage: curlu [options...] <url>

HTTP(S)-only curl-compatible client using uTLS and HTTP/1.1.

Options:
  -i, --include                 Include response headers in stdout
  -H, --header <header>         Add, replace, or suppress a request header
  -s, --silent                  Suppress error diagnostics
  -S, --show-error              Show errors when used with --silent
      --connect-timeout <secs>  Limit DNS, TCP, and TLS connection time
  -m, --max-time <secs>         Limit the complete transfer time
      --utls-hello <id>         Select a uTLS ClientHello ID (HelloChrome_120)
      --utls-hello-list         List supported uTLS ClientHello IDs
      --utls-cipher-append <id> Append a 0xNNNN cipher ID (repeatable)
      --utls-info               Print EXPECTED_CIPHER_COUNT to stderr
  -h, --help                    Show this help
  -V, --version                 Show version information

WARNING: HTTPS certificate verification is always disabled.
Only one explicit http:// or https:// URL and the GET method are supported.
Proxies, redirects, request bodies, and HTTP/2 are not supported.
`

func Run(args []string, stdout, stderr io.Writer, version string) int {
	opts, err := ParseArgs(args)
	if err != nil {
		return report(stderr, opts, 2, err.Error())
	}
	if opts.Help {
		if _, err := io.WriteString(stdout, helpText); err != nil {
			return report(stderr, opts, 23, "failed writing output")
		}
		return 0
	}
	if opts.Version {
		if _, err := fmt.Fprintf(stdout, "curlu %s (uTLS 1.8.2)\nProtocols: http https\n", version); err != nil {
			return report(stderr, opts, 23, "failed writing output")
		}
		return 0
	}
	if opts.UTLSHelloList {
		if _, err := fmt.Fprintln(stdout, strings.Join(utlsHelloNames(), "\n")); err != nil {
			return report(stderr, opts, 23, "failed writing output")
		}
		return 0
	}
	exitErr := execute(opts, stdout, stderr, version)
	if exitErr == nil {
		return 0
	}
	return report(stderr, opts, exitErr.Code, exitErr.Message)
}

func report(stderr io.Writer, opts Options, code int, message string) int {
	if !opts.Silent || opts.ShowError {
		_, _ = fmt.Fprintf(stderr, "curlu: (%d) %s\n", code, message)
	}
	return code
}

type ExitError struct {
	Code    int
	Message string
}

func fail(code int, format string, args ...any) *ExitError {
	return &ExitError{Code: code, Message: fmt.Sprintf(format, args...)}
}
