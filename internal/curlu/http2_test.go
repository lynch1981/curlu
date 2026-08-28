package curlu

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHTTP2ParrotGET(t *testing.T) {
	var proto, userAgent, accept string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		userAgent = r.UserAgent()
		accept = r.Header.Get("Accept")
		w.Header().Set("X-Test", "yes")
		_, _ = io.WriteString(w, "secure")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"-i", "-s", "--utls-hello", "HelloChrome_102", "--max-time", "2", server.URL}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if proto != "HTTP/2.0" {
		t.Fatalf("proto = %q", proto)
	}
	if userAgent != "curlu/test" {
		t.Fatalf("User-Agent = %q", userAgent)
	}
	if accept != "*/*" {
		t.Fatalf("Accept = %q", accept)
	}
	got := stdout.String()
	if !strings.HasPrefix(got, "HTTP/2 200\r\n") {
		t.Fatalf("stdout = %q", got)
	}
	if !strings.Contains(got, "x-test: yes\r\n") {
		t.Fatalf("missing x-test header: %q", got)
	}
	if !strings.HasSuffix(got, "\r\n\r\nsecure") {
		t.Fatalf("stdout = %q", got)
	}
}

func TestHTTP2FirefoxParrotGET(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-s", "--utls-hello", "HelloFirefox_55", "--max-time", "2", server.URL}, &stdout, &stderr, "test"); code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if stdout.String() != "ok" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestHTTP2HeaderSuppression(t *testing.T) {
	var userAgent, accept string
	var hasUA, hasAccept bool
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, hasUA = r.Header["User-Agent"]
		_, hasAccept = r.Header["Accept"]
		userAgent = r.UserAgent()
		accept = r.Header.Get("Accept")
		w.WriteHeader(http.StatusNoContent)
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := Run([]string{
		"-s", "--utls-hello", "HelloChrome_102",
		"-H", "User-Agent:", "-H", "Accept:",
		"--max-time", "2", server.URL,
	}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if hasUA || userAgent != "" {
		t.Fatalf("User-Agent sent: present=%v value=%q", hasUA, userAgent)
	}
	if hasAccept || accept != "" {
		t.Fatalf("Accept sent: present=%v value=%q", hasAccept, accept)
	}
	if strings.Contains(userAgent, "Go-http-client") {
		t.Fatalf("Go default User-Agent leaked: %q", userAgent)
	}
}

func TestHelloGolangStaysHTTP1OnHTTP2Server(t *testing.T) {
	var proto string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		_, _ = io.WriteString(w, "h1")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"-i", "-s", "--max-time", "2", server.URL}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if proto != "HTTP/1.1" {
		t.Fatalf("proto = %q", proto)
	}
	if !strings.HasPrefix(stdout.String(), "HTTP/1.1 200") {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if strings.Contains(stdout.String(), "HTTP/2") {
		t.Fatalf("unexpected HTTP/2 output: %q", stdout.String())
	}
}
