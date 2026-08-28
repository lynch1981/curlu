package curlu

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerboseHTTP1Trace(t *testing.T) {
	url, received := serveRaw(t, "HTTP/1.1 200 OK\r\nX-Test: yes\r\nContent-Length: 2\r\n\r\nok", 0)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-v", url + "/health"}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != "ok" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.HasPrefix(<-received, "GET /health HTTP/1.1\r\n") {
		t.Fatal("request not received")
	}
	trace := stderr.String()
	for _, want := range []string{
		"* Trying 127.0.0.1:",
		"* Connected to 127.0.0.1 (127.0.0.1) port ",
		"> GET /health HTTP/1.1",
		"> Host: 127.0.0.1:",
		"> User-Agent: curlu/test",
		"> Accept: */*",
		"> \n",
		"< HTTP/1.1 200 OK",
		"< X-Test: yes",
		"< \n",
		"* Closing connection\n",
	} {
		if !strings.Contains(trace, want) {
			t.Errorf("stderr missing %q:\n%s", want, trace)
		}
	}
	if strings.Contains(stdout.String(), "* ") || strings.Contains(stdout.String(), "> GET") {
		t.Fatalf("trace leaked to stdout: %q", stdout.String())
	}
}

func TestVerboseIncludeKeepsStdoutHeaders(t *testing.T) {
	response := "HTTP/1.1 204 No Content\r\nX-Test: yes\r\n\r\n"
	url, _ := serveRaw(t, response, 0)
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-iv", url}, &stdout, &stderr, "test"); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != response {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if !strings.Contains(stderr.String(), "< HTTP/1.1 204 No Content") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestSilentVerboseStillTraces(t *testing.T) {
	url, _ := serveRaw(t, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", 0)
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-sv", url}, &stdout, &stderr, "test"); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if !strings.Contains(stderr.String(), "> GET / HTTP/1.1") {
		t.Fatalf("stderr = %q", stderr.String())
	}

	var errOut bytes.Buffer
	if code := Run([]string{"-sv", "not-a-url"}, &stdout, &errOut, "test"); code != 3 {
		t.Fatalf("code = %d", code)
	}
	if errOut.Len() != 0 {
		t.Fatalf("silent error leaked: %q", errOut.String())
	}
}

func TestVerboseHTTPS(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "secure")
	}))
	server.EnableHTTP2 = false
	server.StartTLS()
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"-sv", "--max-time", "2", server.URL}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != "secure" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	trace := stderr.String()
	if !strings.Contains(trace, "* SSL connection using ") {
		t.Fatalf("missing TLS line:\n%s", trace)
	}
	if !strings.Contains(trace, "* SSL certificate verification is disabled") {
		t.Fatalf("missing verify line:\n%s", trace)
	}
	if !strings.Contains(trace, "* ALPN: server accepted http/1.1") {
		t.Fatalf("missing ALPN line:\n%s", trace)
	}
}

func TestVerboseHTTP2(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || r.TLS.NegotiatedProtocol != "h2" {
			t.Errorf("negotiated = %v", r.TLS)
		}
		w.Header().Set("X-Test", "yes")
		_, _ = io.WriteString(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"-sv", "--utls-hello", "HelloChrome_102", "--max-time", "2", server.URL + "/x"}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != "ok" {
		t.Fatalf("stdout = %q", stdout.String())
	}
	trace := stderr.String()
	for _, want := range []string{
		"* ALPN: server accepted h2",
		"> GET /x HTTP/2",
		"> Host: 127.0.0.1:",
		"> User-Agent: curlu/test",
		"< HTTP/2 200",
		"< x-test: yes",
	} {
		if !strings.Contains(trace, want) {
			t.Errorf("stderr missing %q:\n%s", want, trace)
		}
	}
}

func TestVerboseLongOption(t *testing.T) {
	opts, err := ParseArgs([]string{"--verbose", "http://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.Verbose {
		t.Fatal("Verbose is false")
	}
}
