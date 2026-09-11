package curlu

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"
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
	code := Run([]string{"-i", "-sk", "--http2-prior-knowledge", "--utls-hello", "HelloChrome_102", "--max-time", "2", server.URL}, &stdout, &stderr, "test")
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
	if code := Run([]string{"-sk", "--utls-hello", "HelloFirefox_55", "--max-time", "2", server.URL}, &stdout, &stderr, "test"); code != 0 {
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
		"-sk", "--utls-hello", "HelloChrome_102",
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
	code := Run([]string{"-i", "-sk", "--max-time", "2", server.URL}, &stdout, &stderr, "test")
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

func TestHelloGolangPriorKnowledgeStaysHTTP1OnHTTPS(t *testing.T) {
	var proto string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		_, _ = io.WriteString(w, "h1")
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"-i", "-sk", "--http2-prior-knowledge", "--max-time", "2", server.URL}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if proto != "HTTP/1.1" {
		t.Fatalf("proto = %q", proto)
	}
	if !strings.HasPrefix(stdout.String(), "HTTP/1.1 200") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func TestHTTP2PriorKnowledgeH2C(t *testing.T) {
	var proto, userAgent, accept string
	url := serveH2C(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		proto = r.Proto
		userAgent = r.UserAgent()
		accept = r.Header.Get("Accept")
		w.Header().Set("X-Test", "yes")
		_, _ = io.WriteString(w, "h2c")
	}))

	var stdout, stderr bytes.Buffer
	code := Run([]string{"-i", "--http2-prior-knowledge", "--max-time", "2", url + "/health"}, &stdout, &stderr, "test")
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
	if !strings.HasSuffix(got, "\r\n\r\nh2c") {
		t.Fatalf("stdout = %q", got)
	}
}

func TestHTTP2PriorKnowledgeSendsH2CPreface(t *testing.T) {
	url, first := captureClientPreface(t)
	var stdout, stderr bytes.Buffer
	_ = Run([]string{"--http2-prior-knowledge", "--max-time", "1", url}, &stdout, &stderr, "test")
	got := recvPreface(t, first)
	if !bytes.HasPrefix(got, []byte("PRI * HTTP/2.0")) {
		t.Fatalf("preface = %q", got)
	}
}

func TestHTTPWithoutPriorKnowledgeSendsHTTP1(t *testing.T) {
	url, first := captureClientPreface(t)
	var stdout, stderr bytes.Buffer
	_ = Run([]string{"--max-time", "1", url}, &stdout, &stderr, "test")
	got := recvPreface(t, first)
	if !bytes.HasPrefix(got, []byte("GET ")) {
		t.Fatalf("request = %q", got)
	}
}

func TestHTTP2PriorKnowledgeAgainstHTTP1(t *testing.T) {
	url, _ := serveRaw(t, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 0)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"--http2-prior-knowledge", "--max-time", "2", url}, &stdout, &stderr, "test")
	if code != 55 && code != 56 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
}

func serveH2C(t *testing.T, handler http.Handler) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	h2s := &http2.Server{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go h2s.ServeConn(conn, &http2.ServeConnOpts{Handler: handler})
		}
	}()
	return "http://" + ln.Addr().String()
}

func captureClientPreface(t *testing.T) (string, <-chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	first := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			first <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 24)
		n, _ := io.ReadAtLeast(conn, buf, 3)
		first <- buf[:n]
	}()
	return "http://" + ln.Addr().String() + "/", first
}

func recvPreface(t *testing.T, first <-chan []byte) []byte {
	t.Helper()
	select {
	case got := <-first:
		return got
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for client bytes")
		return nil
	}
}
