package curlu

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	utls "github.com/refraction-networking/utls"
)

const maxResponseHeaderBytes = 1 << 20

var (
	dialContext        = (&net.Dialer{}).DialContext
	errHeadersTooLarge = fmt.Errorf("response headers exceed %d bytes", maxResponseHeaderBytes)
)

func execute(opts Options, stdout io.Writer, version string) *ExitError {
	target, exitErr := parseURL(opts.URL)
	if exitErr != nil {
		return exitErr
	}
	request, exitErr := buildRequest(target, opts.Headers, version)
	if exitErr != nil {
		return exitErr
	}

	operationCtx := context.Background()
	var cancelOperation context.CancelFunc = func() {}
	if opts.MaxTime > 0 {
		operationCtx, cancelOperation = context.WithTimeout(operationCtx, opts.MaxTime)
	}
	defer cancelOperation()

	connectCtx := operationCtx
	var cancelConnect context.CancelFunc = func() {}
	if opts.ConnectTimeout > 0 {
		connectCtx, cancelConnect = context.WithTimeout(operationCtx, opts.ConnectTimeout)
	}
	defer cancelConnect()

	port := target.Port()
	if port == "" {
		if target.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	conn, err := dialContext(connectCtx, "tcp", net.JoinHostPort(target.Hostname(), port))
	if err != nil {
		return connectFailure(err)
	}
	defer conn.Close()

	if target.Scheme == "https" {
		serverName := ""
		if net.ParseIP(target.Hostname()) == nil {
			serverName = target.Hostname()
		}
		tlsConn := utls.UClient(conn, &utls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true, // Deliberate curlu v1 policy.
			NextProtos:         []string{"http/1.1"},
		}, utls.HelloGolang)
		if err := tlsConn.HandshakeContext(connectCtx); err != nil {
			if isTimeout(err) || connectCtx.Err() != nil {
				return fail(28, "connection timed out")
			}
			return fail(35, "TLS handshake failed: %v", err)
		}
		conn = tlsConn
	}
	cancelConnect()

	if deadline, ok := operationCtx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return fail(55, "failed setting transfer deadline: %v", err)
		}
	}
	if err := writeAll(conn, request); err != nil {
		if isTimeout(err) || operationCtx.Err() != nil {
			return fail(28, "operation timed out")
		}
		return fail(55, "failed sending request: %v", err)
	}
	return readResponse(conn, stdout, opts.Include, operationCtx)
}

func parseURL(raw string) (*url.URL, *ExitError) {
	target, err := url.Parse(raw)
	if err != nil || target.Scheme == "" || target.Host == "" {
		return nil, fail(3, "malformed URL")
	}
	switch strings.ToLower(target.Scheme) {
	case "http", "https":
		target.Scheme = strings.ToLower(target.Scheme)
	default:
		return nil, fail(1, "unsupported protocol %q", target.Scheme)
	}
	if target.User != nil || target.Hostname() == "" {
		return nil, fail(3, "malformed URL")
	}
	if target.Port() != "" {
		if _, err := strconv.ParseUint(target.Port(), 10, 16); err != nil {
			return nil, fail(3, "malformed URL port")
		}
	}
	return target, nil
}

type requestHeader struct {
	name, wire string
	suppress   bool
}

func buildRequest(target *url.URL, values []string, version string) ([]byte, *ExitError) {
	headers := make([]requestHeader, 0, len(values))
	suppressedDefaults := make(map[string]bool)
	for _, value := range values {
		header, err := parseRequestHeader(value)
		if err != nil {
			return nil, fail(2, "invalid header %q: %v", value, err)
		}
		headers = append(headers, header)
		lowerName := strings.ToLower(header.name)
		if lowerName == "host" || lowerName == "user-agent" || lowerName == "accept" {
			suppressedDefaults[lowerName] = true
		}
	}
	var request bytes.Buffer
	fmt.Fprintf(&request, "GET %s HTTP/1.1\r\n", target.RequestURI())
	if !suppressedDefaults["host"] {
		fmt.Fprintf(&request, "Host: %s\r\n", requestHost(target))
	}
	if !suppressedDefaults["user-agent"] {
		fmt.Fprintf(&request, "User-Agent: curlu/%s\r\n", safeVersion(version))
	}
	if !suppressedDefaults["accept"] {
		request.WriteString("Accept: */*\r\n")
	}
	for _, header := range headers {
		if !header.suppress {
			request.WriteString(header.wire)
			request.WriteString("\r\n")
		}
	}
	request.WriteString("\r\n")
	return request.Bytes(), nil
}

func requestHost(target *url.URL) string {
	host := target.Hostname()
	port := target.Port()
	if port == "" || (target.Scheme == "http" && port == "80") || (target.Scheme == "https" && port == "443") {
		if strings.Contains(host, ":") {
			return "[" + host + "]"
		}
		return host
	}
	return net.JoinHostPort(host, port)
}

func parseRequestHeader(value string) (requestHeader, error) {
	if strings.ContainsAny(value, "\r\n\x00") {
		return requestHeader{}, fmt.Errorf("control characters are not allowed")
	}
	colon := strings.IndexByte(value, ':')
	if colon <= 0 {
		return requestHeader{}, fmt.Errorf("expected Name: value")
	}
	name := strings.TrimSpace(value[:colon])
	if !validHeaderName(name) {
		return requestHeader{}, fmt.Errorf("invalid field name")
	}
	rest := value[colon+1:]
	if strings.TrimSpace(rest) == "" {
		return requestHeader{name: name, suppress: true}, nil
	}
	return requestHeader{name: name, wire: name + ":" + rest}, nil
}

func validHeaderName(name string) bool {
	if name == "" {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '!', '#', '$', '%', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
			continue
		default:
			return false
		}
	}
	return true
}

func safeVersion(version string) string {
	version = strings.Map(func(r rune) rune {
		if r < 0x21 || r > 0x7e {
			return '-'
		}
		return r
	}, version)
	if version == "" {
		return "dev"
	}
	return version
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := writer.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

func readResponse(conn net.Conn, stdout io.Writer, include bool, ctx context.Context) *ExitError {
	reader := bufio.NewReader(conn)
	request := &http.Request{Method: http.MethodGet}
	var body io.Closer
	defer func() {
		if body != nil {
			_ = body.Close()
		}
	}()
	for {
		headerBlock, response, next, err := readNextResponse(reader, request)
		if err != nil {
			return receiveError(err, ctx)
		}
		if response.StatusCode >= 100 && response.StatusCode < 200 && response.StatusCode != http.StatusSwitchingProtocols {
			_ = response.Body.Close()
			if include {
				if err := writeAll(stdout, headerBlock); err != nil {
					return fail(23, "failed writing output")
				}
			}
			reader = next
			continue
		}
		if response.StatusCode == http.StatusSwitchingProtocols {
			_ = response.Body.Close()
			return fail(8, "protocol upgrades are not supported")
		}
		body = response.Body
		if include {
			if err := writeAll(stdout, headerBlock); err != nil {
				return fail(23, "failed writing output")
			}
		}
		tracker := &trackingWriter{writer: stdout}
		_, copyErr := io.Copy(tracker, response.Body)
		if tracker.err != nil {
			return fail(23, "failed writing output")
		}
		if copyErr != nil {
			if isTimeout(copyErr) || ctx.Err() != nil {
				return fail(28, "operation timed out")
			}
			if errors.Is(copyErr, io.ErrUnexpectedEOF) {
				return fail(18, "partial response body")
			}
			return fail(56, "failed receiving response: %v", copyErr)
		}
		return nil
	}
}

type headerBlockError struct {
	n   int
	err error
}

func (e *headerBlockError) Error() string { return e.err.Error() }
func (e *headerBlockError) Unwrap() error { return e.err }

func readNextResponse(reader *bufio.Reader, request *http.Request) ([]byte, *http.Response, *bufio.Reader, error) {
	headerBlock, err := readHeaderBlock(reader)
	if err != nil {
		return headerBlock, nil, reader, &headerBlockError{n: len(headerBlock), err: err}
	}
	next := bufio.NewReader(io.MultiReader(bytes.NewReader(headerBlock), reader))
	response, err := http.ReadResponse(next, request)
	if err != nil {
		return headerBlock, nil, next, err
	}
	return headerBlock, response, next, nil
}

func receiveError(err error, ctx context.Context) *ExitError {
	if isTimeout(err) || ctx.Err() != nil {
		return fail(28, "operation timed out")
	}
	var headerErr *headerBlockError
	if errors.As(err, &headerErr) {
		if errors.Is(headerErr.err, errHeadersTooLarge) {
			return fail(8, "invalid HTTP response: %v", headerErr.err)
		}
		if errors.Is(headerErr.err, io.EOF) && headerErr.n == 0 {
			return fail(52, "empty reply from server")
		}
		return fail(56, "failed receiving response: %v", headerErr.err)
	}
	return fail(8, "invalid HTTP response: %v", err)
}

func readHeaderBlock(reader *bufio.Reader) ([]byte, error) {
	var block bytes.Buffer
	lineStart := 0
	for {
		if block.Len() >= maxResponseHeaderBytes {
			return nil, errHeadersTooLarge
		}
		fragment, err := reader.ReadSlice('\n')
		if block.Len()+len(fragment) > maxResponseHeaderBytes {
			return nil, errHeadersTooLarge
		}
		block.Write(fragment)
		if err == bufio.ErrBufferFull {
			continue
		}
		if err != nil {
			return block.Bytes(), err
		}
		line := block.Bytes()[lineStart:]
		if bytes.Equal(line, []byte("\r\n")) || bytes.Equal(line, []byte("\n")) {
			return block.Bytes(), nil
		}
		lineStart = block.Len()
	}
}

type trackingWriter struct {
	writer io.Writer
	err    error
}

func (w *trackingWriter) Write(data []byte) (int, error) {
	n, err := w.writer.Write(data)
	if err == nil && n != len(data) {
		err = io.ErrShortWrite
	}
	if err != nil {
		w.err = err
	}
	return n, err
}

func connectFailure(err error) *ExitError {
	if isTimeout(err) {
		return fail(28, "connection timed out")
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return fail(6, "could not resolve host: %v", dnsErr)
	}
	return fail(7, "failed to connect: %v", err)
}

func isTimeout(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
