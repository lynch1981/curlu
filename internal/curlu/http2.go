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

func roundTripHTTP2(conn net.Conn, target *url.URL, headers []requestHeader, suppressed map[string]bool, stdout io.Writer, include bool, version string, ctx context.Context, tr trace) *ExitError {
	req := buildHTTP2Request(target, headers, suppressed, version).WithContext(ctx)
	tr.dump("> ", formatHTTP2VerboseRequest(req))

	transport := &http2.Transport{
		DisableCompression: true,
		MaxHeaderListSize:  maxResponseHeaderBytes,
	}
	clientConn, err := transport.NewClientConn(conn)
	if err != nil {
		return http2SendError(err, ctx)
	}
	defer clientConn.Close()

	response, err := clientConn.RoundTrip(req)
	if err != nil {
		return http2ReceiveError(err, ctx)
	}
	defer response.Body.Close()
	headerBlock := formatHTTP2Headers(response)
	tr.dump("< ", headerBlock)

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

func buildHTTP2Request(target *url.URL, headers []requestHeader, suppressed map[string]bool, version string) *http.Request {
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        target,
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
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

func formatHTTP2VerboseRequest(req *http.Request) []byte {
	var block strings.Builder
	fmt.Fprintf(&block, "GET %s HTTP/2\r\nHost: %s\r\n", req.URL.RequestURI(), req.Host)
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

func formatHTTP2Headers(response *http.Response) []byte {
	var block strings.Builder
	fmt.Fprintf(&block, "HTTP/2 %d\r\n", response.StatusCode)
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
