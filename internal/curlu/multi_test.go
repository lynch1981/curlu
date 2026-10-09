package curlu

import (
	"bytes"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestExpandGlob(t *testing.T) {
	tests := []struct {
		raw  string
		want []string
	}{
		{"http://h/t", []string{"http://h/t"}},
		{"http://h", []string{"http://h"}},
		{"http://h/t?r={1,2}", []string{"http://h/t?r=1", "http://h/t?r=2"}},
		{"http://h?r={a,}", []string{"http://h?r=a", "http://h?r="}},
		{"http://h/{a,b}/[1-2]", []string{"http://h/a/1", "http://h/a/2", "http://h/b/1", "http://h/b/2"}},
		{"http://h/[08-10]", []string{"http://h/08", "http://h/09", "http://h/10"}},
		{"http://h/[0-1]", []string{"http://h/0", "http://h/1"}},
		{`http://h/\{a,b\}\[1\]`, []string{"http://h/{a,b}[1]"}},
		{`http://h/a\b`, []string{`http://h/a\b`}},
		{"http://[::1]:80/{x,y}", []string{"http://[::1]:80/x", "http://[::1]:80/y"}},
	}
	for _, tc := range tests {
		got, err := expandGlob(tc.raw)
		if err != nil {
			t.Errorf("expandGlob(%q): %v", tc.raw, err)
			continue
		}
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("expandGlob(%q) = %q, want %q", tc.raw, got, tc.want)
		}
	}
}

func TestExpandGlobErrors(t *testing.T) {
	for _, raw := range []string{
		"http://h/{a,b", "http://h/a}", "http://h/[1-2", "http://h/]",
		"http://h/[2-1]", "http://h/[a-z]", "http://h/[1]", "http://h/[0-1000]",
		"http://h/[0-99][0-99]",
	} {
		if got, err := expandGlob(raw); err == nil {
			t.Errorf("expandGlob(%q) = %q, want error", raw, got)
		}
	}
}

// countConns counts the TCP connections a test server accepts.
func countConns(server *httptest.Server) func() int {
	var mu sync.Mutex
	n := 0
	server.Config.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateNew {
			mu.Lock()
			n++
			mu.Unlock()
		}
	}
	return func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

func echoPathQuery(w http.ResponseWriter, r *http.Request) {
	_, _ = io.WriteString(w, r.Proto+" "+r.URL.RequestURI()+"\n")
}

func TestMultiURLHTTP1ReusesConnection(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(echoPathQuery))
	conns := countConns(server)
	server.Start()
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"-sv", "--max-time", "2", server.URL + "/t?r={1,2}", server.URL + "/u"}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if want := "HTTP/1.1 /t?r=1\nHTTP/1.1 /t?r=2\nHTTP/1.1 /u\n"; stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	if n := conns(); n != 1 {
		t.Fatalf("connections = %d, want 1", n)
	}
	if n := strings.Count(stderr.String(), "* Re-using existing connection\n"); n != 2 {
		t.Fatalf("reuse lines = %d, stderr = %q", n, stderr.String())
	}
}

func TestMultiURLHTTP1ReconnectsAfterClose(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Connection", "close")
		echoPathQuery(w, r)
	}))
	conns := countConns(server)
	server.Start()
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"-s", "--max-time", "2", server.URL + "/[1-2]"}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if want := "HTTP/1.1 /1\nHTTP/1.1 /2\n"; stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	if n := conns(); n != 2 {
		t.Fatalf("connections = %d, want 2", n)
	}
}

func TestMultiURLHTTP2SharesConnection(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(echoPathQuery))
	server.EnableHTTP2 = true
	conns := countConns(server)
	server.StartTLS()
	defer server.Close()

	var stdout, stderr bytes.Buffer
	code := Run([]string{"-sk", "--utls-hello", "HelloChrome_120", "--max-time", "2", server.URL + "/t?r={1,2}"}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if want := "HTTP/2.0 /t?r=1\nHTTP/2.0 /t?r=2\n"; stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
	if n := conns(); n != 1 {
		t.Fatalf("connections = %d, want 1", n)
	}
}

func TestMultiURLH2CSharesConnection(t *testing.T) {
	url := serveH2C(t, http.HandlerFunc(echoPathQuery))

	var stdout, stderr bytes.Buffer
	code := Run([]string{"-s", "--http2-prior-knowledge", "--max-time", "2", url + "/a", url + "/b"}, &stdout, &stderr, "test")
	if code != 0 {
		t.Fatalf("code = %d, stderr = %q", code, stderr.String())
	}
	if want := "HTTP/2.0 /a\nHTTP/2.0 /b\n"; stdout.String() != want {
		t.Fatalf("stdout = %q, want %q", stdout.String(), want)
	}
}

func TestGloboffSendsBracesLiterally(t *testing.T) {
	var query string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
	}))
	defer server.Close()

	var stdout, stderr bytes.Buffer
	for _, flag := range []string{"-g", "--globoff"} {
		if code := Run([]string{"-s", flag, "--max-time", "2", server.URL + "/t?r={1,2}"}, &stdout, &stderr, "test"); code != 0 {
			t.Fatalf("%s: code = %d, stderr = %q", flag, code, stderr.String())
		}
		if query != "r={1,2}" {
			t.Fatalf("%s: query = %q", flag, query)
		}
	}
}

func TestMultiURLErrors(t *testing.T) {
	tests := []struct {
		args []string
		code int
	}{
		{[]string{"http://a.test/", "http://b.test/"}, 2},
		{[]string{"http://a.test/", "https://a.test/"}, 2},
		{[]string{"http://a.test/", "http://a.test:8080/"}, 2},
		{[]string{"http://a.test/{x,y"}, 3},
		{[]string{"http://a.test/", "ftp://a.test/"}, 1},
	}
	for _, tc := range tests {
		var stdout, stderr bytes.Buffer
		if code := Run(tc.args, &stdout, &stderr, "test"); code != tc.code {
			t.Errorf("Run(%q) = %d, want %d (stderr %q)", tc.args, code, tc.code, stderr.String())
		}
	}
}

func TestParseTargetsDefaultPortMatchesExplicit(t *testing.T) {
	targets, exitErr := parseTargets(Options{URLs: []string{"http://A.test/x", "http://a.test:80/y", "http://a.test:080/z"}})
	if exitErr != nil {
		t.Fatal(exitErr.Message)
	}
	if len(targets) != 3 {
		t.Fatalf("targets = %d", len(targets))
	}
}
