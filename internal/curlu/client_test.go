package curlu

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestExactRequestAndIncludedResponse(t *testing.T) {
	response := "HTTP/1.1 200 OK\r\nX-Test: yes\r\nContent-Length: 2\r\n\r\nok"
	url, received := serveRaw(t, response, 0)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-i", "-H", "User-Agent:", "-H", "Accept:", "-H", "Host:", "-sS", "--connect-timeout", "1", "--max-time", "1", url + "/health?q=1"}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if got, want := <-received, "GET /health?q=1 HTTP/1.1\r\n\r\n"; got != want {
		t.Fatalf("request:\n%q\nwant:\n%q", got, want)
	}
	if stdout.String() != response {
		t.Fatalf("stdout = %q, want %q", stdout.String(), response)
	}
	if stderr.Len() != 0 {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestDefaultAndCustomHeaders(t *testing.T) {
	url, received := serveRaw(t, "HTTP/1.1 204 No Content\r\n\r\n", 0)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-H", "X-One: first", "-H", "X-One:second", url}, &stdout, &stderr, "1.2.3")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	request := <-received
	for _, want := range []string{"Host: 127.0.0.1:", "User-Agent: curlu/1.2.3\r\n", "Accept: */*\r\n", "X-One: first\r\n", "X-One:second\r\n"} {
		if !strings.Contains(request, want) {
			t.Errorf("request missing %q:\n%s", want, request)
		}
	}
}

func TestChunkedResponseIsDecoded(t *testing.T) {
	url, _ := serveRaw(t, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n", 0)
	var stdout, stderr bytes.Buffer
	if code := Run([]string{url}, &stdout, &stderr, "test"); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != "Wikipedia" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestInformationalResponseIsIncluded(t *testing.T) {
	response := "HTTP/1.1 100 Continue\r\nX-Interim: yes\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
	url, _ := serveRaw(t, response, 0)
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-i", url}, &stdout, &stderr, "test"); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != response {
		t.Fatalf("stdout = %q, want %q", stdout.String(), response)
	}
}

func TestPartialAndTimedOutResponses(t *testing.T) {
	t.Run("partial", func(t *testing.T) {
		url, _ := serveRaw(t, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhi", 0)
		var stdout, stderr bytes.Buffer
		if code := Run([]string{url}, &stdout, &stderr, "test"); code != 18 {
			t.Fatalf("code = %d, stderr = %q", code, stderr.String())
		}
	})
	t.Run("max time", func(t *testing.T) {
		url, _ := serveRaw(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 150*time.Millisecond)
		var stdout, stderr bytes.Buffer
		if code := Run([]string{"--max-time", "0.03", url}, &stdout, &stderr, "test"); code != 28 {
			t.Fatalf("code = %d, stderr = %q", code, stderr.String())
		}
	})
}

func TestConnectTimeout(t *testing.T) {
	originalDial := dialContext
	dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	t.Cleanup(func() { dialContext = originalDial })
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--connect-timeout", "0.02", "http://example.test/"}, &stdout, &stderr, "test"); code != 28 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestDNSErrorMapping(t *testing.T) {
	originalDial := dialContext
	dialContext = func(context.Context, string, string) (net.Conn, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "example.test", IsNotFound: true}
	}
	t.Cleanup(func() { dialContext = originalDial })
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"http://example.test/"}, &stdout, &stderr, "test"); code != 6 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestHTTPSAcceptsSelfSignedCertificate(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "secure") }))
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"--max-time", "2", server.URL}, &stdout, &stderr, "test"); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != "secure" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestDiagnosticsAndExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		args      []string
		code      int
		wantError bool
	}{
		{"silent", []string{"-s", "not-a-url"}, 3, false},
		{"show error", []string{"-sS", "not-a-url"}, 3, true},
		{"unsupported", []string{"ftp://example.test/"}, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(tc.args, &stdout, &stderr, "test"); code != tc.code {
				t.Fatalf("code = %d, want %d", code, tc.code)
			}
			if got := stderr.Len() > 0; got != tc.wantError {
				t.Fatalf("stderr = %q", stderr.String())
			}
		})
	}
}

func TestOutputWriteFailure(t *testing.T) {
	url, _ := serveRaw(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 0)
	var stderr bytes.Buffer
	if code := Run([]string{url}, failingWriter{}, &stderr, "test"); code != 23 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func TestHeaderInjectionRejected(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-H", "X-Test: ok\r\nInjected: yes", "http://127.0.0.1/"}, &stdout, &stderr, "test"); code != 2 {
		t.Fatalf("code = %d", code)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, fmt.Errorf("write failed") }

func serveRaw(t *testing.T, response string, delay time.Duration) (string, <-chan string) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		var request strings.Builder
		for {
			line, err := reader.ReadString('\n')
			request.WriteString(line)
			if err != nil || line == "\r\n" || line == "\n" {
				break
			}
		}
		received <- request.String()
		if delay > 0 {
			time.Sleep(delay)
		}
		_, _ = io.WriteString(conn, response)
	}()
	return "http://" + listener.Addr().String(), received
}
