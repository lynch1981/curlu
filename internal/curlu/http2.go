package curlu

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"golang.org/x/net/http2"
)

// roundTripHTTP2 sends one stream per target, in order, on a single HTTP/2
// connection.
func roundTripHTTP2(conn net.Conn, targets []*url.URL, headers []requestHeader, suppressed map[string]bool, stdout io.Writer, include bool, version string, ctx context.Context, tr trace) *ExitError {
	transport := &http2.Transport{
		DisableCompression: true,
		MaxHeaderListSize:  maxResponseHeaderBytes,
	}
	clientConn, err := transport.NewClientConn(conn)
	if err != nil {
		return http2SendError(err, ctx)
	}
	defer clientConn.Close()

	mux := muxedRequests{
		major:        2,
		roundTrip:    clientConn.RoundTrip,
		receiveError: http2ReceiveError,
		headers:      headers,
		suppressed:   suppressed,
		stdout:       stdout,
		include:      include,
		version:      version,
		tr:           tr,
	}
	return mux.run(ctx, targets)
}

// muxedRequests runs GETs as streams on one HTTP/2 or HTTP/3 connection.
type muxedRequests struct {
	major        int
	roundTrip    func(*http.Request) (*http.Response, error)
	receiveError func(error, context.Context) *ExitError
	headers      []requestHeader
	suppressed   map[string]bool
	stdout       io.Writer
	include      bool
	version      string
	tr           trace
}

func (m muxedRequests) run(ctx context.Context, targets []*url.URL) *ExitError {
	for i, target := range targets {
		if i > 0 {
			m.tr.info("Re-using existing connection")
		}
		if exitErr := m.stream(ctx, target); exitErr != nil {
			return exitErr
		}
	}
	return nil
}

func (m muxedRequests) stream(ctx context.Context, target *url.URL) *ExitError {
	req := buildMuxedRequest(target, m.major, m.headers, m.suppressed, m.version).WithContext(ctx)
	m.tr.dump("> ", formatMuxedRequest(req, m.major))

	response, err := m.roundTrip(req)
	if err != nil {
		return m.receiveError(err, ctx)
	}
	defer response.Body.Close()
	headerBlock := formatMuxedHeaders(response, m.major)
	m.tr.dump("< ", headerBlock)

	if m.include {
		if err := writeAll(m.stdout, headerBlock); err != nil {
			return fail(23, "failed writing output")
		}
	}
	tracker := &trackingWriter{writer: m.stdout}
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

func buildMuxedRequest(target *url.URL, major int, headers []requestHeader, suppressed map[string]bool, version string) *http.Request {
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        target,
		Proto:      fmt.Sprintf("HTTP/%d.0", major),
		ProtoMajor: major,
		Header:     make(http.Header),
		Host:       requestHost(target),
	}
	if !suppressed["user-agent"] {
		req.Header.Set("User-Agent", "curlu/"+safeVersion(version))
	} else {
		req.Header["User-Agent"] = nil
	}
	if !suppressed["accept"] {
		req.Header.Set("Accept", "*/*")
	}
	for _, header := range headers {
		lower := strings.ToLower(header.name)
		if lower == "host" {
			if header.suppress {
				req.Host = requestHost(target)
			} else {
				req.Host = strings.TrimSpace(header.value)
			}
			continue
		}
		if header.suppress || hopByHopHeader(lower) {
			continue
		}
		if lower == "user-agent" {
			req.Header.Set("User-Agent", strings.TrimSpace(header.value))
			continue
		}
		req.Header.Add(header.name, strings.TrimSpace(header.value))
	}
	return req
}

func hopByHopHeader(name string) bool {
	switch name {
	case "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "http2-settings":
		return true
	default:
		return false
	}
}

func formatMuxedRequest(req *http.Request, major int) []byte {
	var block strings.Builder
	fmt.Fprintf(&block, "GET %s HTTP/%d\r\nHost: %s\r\n", req.URL.RequestURI(), major, req.Host)
	writeHeader := func(name string) {
		for _, value := range req.Header[name] {
			fmt.Fprintf(&block, "%s: %s\r\n", name, value)
		}
	}
	writeHeader("User-Agent")
	writeHeader("Accept")
	names := make([]string, 0, len(req.Header))
	for name := range req.Header {
		if name == "User-Agent" || name == "Accept" {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		writeHeader(name)
	}
	block.WriteString("\r\n")
	return []byte(block.String())
}

func formatMuxedHeaders(response *http.Response, major int) []byte {
	var block strings.Builder
	fmt.Fprintf(&block, "HTTP/%d %d\r\n", major, response.StatusCode)
	names := make([]string, 0, len(response.Header))
	for name := range response.Header {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, value := range response.Header[name] {
			fmt.Fprintf(&block, "%s: %s\r\n", strings.ToLower(name), value)
		}
	}
	block.WriteString("\r\n")
	return []byte(block.String())
}

func http2SendError(err error, ctx context.Context) *ExitError {
	if isTimeout(err) || ctx.Err() != nil {
		return fail(28, "operation timed out")
	}
	return fail(55, "failed sending request: %v", err)
}

func http2ReceiveError(err error, ctx context.Context) *ExitError {
	if isTimeout(err) || ctx.Err() != nil {
		return fail(28, "operation timed out")
	}
	if headerListTooLarge(err) {
		return fail(8, "invalid HTTP response: %v", err)
	}
	return fail(56, "failed receiving response: %v", err)
}

func headerListTooLarge(err error) bool {
	msg := err.Error()
	return strings.Contains(msg, "header list too large") || strings.Contains(msg, "HEADERS frame too large")
}
