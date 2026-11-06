package curlu

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func quicTestCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// startHTTP3Server serves handler on a loopback UDP port and returns the port.
func startHTTP3Server(t *testing.T, handler http.HandlerFunc, hello chan<- *tls.ClientHelloInfo) string {
	t.Helper()
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	config := http3.ConfigureTLSConfig(&tls.Config{Certificates: []tls.Certificate{quicTestCert(t)}})
	if hello != nil {
		config.GetConfigForClient = func(info *tls.ClientHelloInfo) (*tls.Config, error) {
			hello <- info
			return nil, nil
		}
	}
	server := &http3.Server{Handler: handler, TLSConfig: config}
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.Serve(socket)
	}()
	t.Cleanup(func() {
		_ = server.Close()
		_ = socket.Close()
		<-done
	})
	return strconv.Itoa(socket.LocalAddr().(*net.UDPAddr).Port)
}

func runHTTP3(t *testing.T, args ...string) (string, string, int) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := Run(append([]string{"--max-time", "5"}, args...), &stdout, &stderr, "test")
	return stdout.String(), stderr.String(), code
}

func TestHTTP3GET(t *testing.T) {
	var mu sync.Mutex
	var proto, host string
	var header http.Header
	port := startHTTP3Server(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		proto, host, header = r.Proto, r.Host, r.Header.Clone()
		mu.Unlock()
		w.Header().Set("X-Test", "yes")
		_, _ = io.WriteString(w, "quic body")
	}, nil)

	stdout, stderr, code := runHTTP3(t, "-i", "-k", "--http3-only", "https://127.0.0.1:"+port+"/t?a=1")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if stderr != "" {
		t.Fatalf("stderr = %q", stderr)
	}
	if !strings.HasPrefix(stdout, "HTTP/3 200\r\n") || !strings.Contains(stdout, "x-test: yes\r\n") || !strings.HasSuffix(stdout, "\r\n\r\nquic body") {
		t.Fatalf("stdout = %q", stdout)
	}
	mu.Lock()
	defer mu.Unlock()
	if proto != "HTTP/3.0" || host != "127.0.0.1:"+port {
		t.Fatalf("proto = %q host = %q", proto, host)
	}
	if header.Get("User-Agent") != "curlu/test" || header.Get("Accept") != "*/*" || header.Get("Accept-Encoding") != "" {
		t.Fatalf("header = %v", header)
	}
}

func TestHTTP3Alias(t *testing.T) {
	port := startHTTP3Server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Proto)
	}, nil)
	stdout, stderr, code := runHTTP3(t, "-k", "--http3", "https://127.0.0.1:"+port+"/")
	if code != 0 || stdout != "HTTP/3.0" {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
}

func TestHTTP3HeaderSuppression(t *testing.T) {
	headers := make(chan http.Header, 1)
	port := startHTTP3Server(t, func(_ http.ResponseWriter, r *http.Request) {
		headers <- r.Header.Clone()
	}, nil)
	_, stderr, code := runHTTP3(t, "-k", "--http3-only", "-H", "User-Agent:", "-H", "Accept:", "-H", "X-One: 1", "https://127.0.0.1:"+port+"/")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	got := <-headers
	if _, ok := got["User-Agent"]; ok {
		t.Fatalf("User-Agent sent: %v", got)
	}
	if _, ok := got["Accept"]; ok {
		t.Fatalf("Accept sent: %v", got)
	}
	if got.Get("X-One") != "1" {
		t.Fatalf("X-One missing: %v", got)
	}
}

func TestHTTP3MultipleURLsShareConnection(t *testing.T) {
	var mu sync.Mutex
	remotes := make(map[string]bool)
	port := startHTTP3Server(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		remotes[r.RemoteAddr] = true
		mu.Unlock()
		_, _ = io.WriteString(w, r.URL.RawQuery+";")
	}, nil)
	stdout, stderr, code := runHTTP3(t, "-k", "--http3-only", "https://127.0.0.1:"+port+"/t?r={1,2,3}")
	if code != 0 || stdout != "r=1;r=2;r=3;" {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(remotes) != 1 {
		t.Fatalf("remotes = %v", remotes)
	}
}

func TestHTTP3ResolveKeepsSNI(t *testing.T) {
	hello := make(chan *tls.ClientHelloInfo, 1)
	port := startHTTP3Server(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, r.Host)
	}, hello)
	host := "h3.example.test"
	stdout, stderr, code := runHTTP3(t, "-k", "--http3-only", "--resolve", host+":"+port+":127.0.0.1", "https://"+host+":"+port+"/")
	if code != 0 || stdout != host+":"+port {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	info := <-hello
	if info.ServerName != host {
		t.Fatalf("SNI = %q", info.ServerName)
	}
	if len(info.SupportedProtos) != 1 || info.SupportedProtos[0] != "h3" {
		t.Fatalf("ALPN = %v", info.SupportedProtos)
	}
}

func TestHTTP3TriesNextAddressAfterRefusal(t *testing.T) {
	port := startHTTP3Server(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, nil)
	host := "h3.example.test"
	stdout, stderr, code := runHTTP3(t, "-k", "--http3-only", "--resolve", host+":"+port+":127.0.0.2,127.0.0.1", "https://"+host+":"+port+"/")
	if code != 0 || stdout != "ok" {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
}

func TestHTTP3CertificateVerification(t *testing.T) {
	port := startHTTP3Server(t, func(http.ResponseWriter, *http.Request) {}, nil)
	_, stderr, code := runHTTP3(t, "--http3-only", "https://127.0.0.1:"+port+"/")
	if code != 60 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

func TestHTTP3NothingListeningFailsFast(t *testing.T) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	port := socket.LocalAddr().(*net.UDPAddr).Port
	socket.Close()

	start := time.Now()
	_, stderr, code := runHTTP3(t, "-k", "--http3-only", fmt.Sprintf("https://127.0.0.1:%d/", port))
	if code != 7 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("took %v", elapsed)
	}
}

func TestHTTP3SilentServerConnectTimeout(t *testing.T) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	port := socket.LocalAddr().(*net.UDPAddr).Port

	start := time.Now()
	_, stderr, code := runHTTP3(t, "-k", "--http3-only", "--connect-timeout", "0.3", fmt.Sprintf("https://127.0.0.1:%d/", port))
	if code != 28 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("took %v", elapsed)
	}
}

func TestHTTP3ConnectTimeoutLongerThanQUICDefault(t *testing.T) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	port := socket.LocalAddr().(*net.UDPAddr).Port

	// quic-go's own handshake limit is 5s and must not cut this attempt short.
	start := time.Now()
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-k", "--http3-only", "--connect-timeout", "6", fmt.Sprintf("https://127.0.0.1:%d/", port)}, &stdout, &stderr, "test")
	if code != 28 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	if elapsed := time.Since(start); elapsed < 5500*time.Millisecond {
		t.Fatalf("gave up after %v", elapsed)
	}
}

func TestHTTP3MaxTimeDuringResponse(t *testing.T) {
	release := make(chan struct{})
	port := startHTTP3Server(t, func(w http.ResponseWriter, _ *http.Request) {
		w.(http.Flusher).Flush()
		_, _ = io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		<-release
	}, nil)
	defer close(release)
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-k", "--http3-only", "--max-time", "0.3", "https://127.0.0.1:" + port + "/"}, &stdout, &stderr, "test")
	if code != 28 || stdout.String() != "partial" {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
}

func TestHTTP3BodyReset(t *testing.T) {
	port := startHTTP3Server(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "partial")
		w.(http.Flusher).Flush()
		// A reset discards unread data, so let the client read it first.
		time.Sleep(200 * time.Millisecond)
		panic(http.ErrAbortHandler)
	}, nil)
	stdout, stderr, code := runHTTP3(t, "-k", "--http3-only", "https://127.0.0.1:"+port+"/")
	if code != 56 || stdout != "partial" {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
}

func TestHTTP3ResetBeforeHeaders(t *testing.T) {
	port := startHTTP3Server(t, func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}, nil)
	stdout, stderr, code := runHTTP3(t, "-k", "--http3-only", "https://127.0.0.1:"+port+"/")
	if code != 95 || stdout != "" {
		t.Fatalf("exit %d stdout %q stderr %q", code, stdout, stderr)
	}
}

func TestHTTP3ALPNMismatch(t *testing.T) {
	socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	listener, err := quic.Listen(socket, &tls.Config{
		Certificates: []tls.Certificate{quicTestCert(t)},
		NextProtos:   []string{"not-h3"},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go func() { _, _ = listener.Accept(context.Background()) }()

	_, stderr, code := runHTTP3(t, "-k", "--http3-only", fmt.Sprintf("https://127.0.0.1:%d/", socket.LocalAddr().(*net.UDPAddr).Port))
	if code != 35 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}

func TestHTTP3Verbose(t *testing.T) {
	port := startHTTP3Server(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, nil)
	_, stderr, code := runHTTP3(t, "-v", "-k", "--http3-only", "https://127.0.0.1:"+port+"/x")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	for _, want := range []string{
		"* Trying 127.0.0.1:" + port + "...\n",
		"* Connected to 127.0.0.1 (127.0.0.1) port " + port + "\n",
		"* SSL connection using TLS 1.3 / ",
		"* ALPN: server accepted h3\n",
		"* using HTTP/3\n",
		"> GET /x HTTP/3\n",
		"< HTTP/3 200\n",
		"* Closing connection\n",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("missing %q in:\n%s", want, stderr)
		}
	}
}

func TestHTTP3IPFamily(t *testing.T) {
	port := startHTTP3Server(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}, nil)
	stdout, stderr, code := runHTTP3(t, "-4", "-k", "--http3-only", "https://127.0.0.1:"+port+"/")
	if code != 0 || stdout != "ok" {
		t.Fatalf("-4: exit %d stdout %q stderr %q", code, stdout, stderr)
	}
	_, stderr, code = runHTTP3(t, "-6", "-k", "--http3-only", "https://127.0.0.1:"+port+"/")
	if code != 7 {
		t.Fatalf("-6: exit %d: %s", code, stderr)
	}
}

func TestHTTP3InvalidCombinations(t *testing.T) {
	cases := [][]string{
		{"--http3-only", "http://127.0.0.1/"},
		{"--http3-only", "--http2-prior-knowledge", "https://127.0.0.1/"},
		{"--http3-only", "--utls-hello", "HelloChrome_120", "https://127.0.0.1/"},
		{"--http3-only", "--utls-alpn-none", "https://127.0.0.1/"},
		{"--http3-only", "--ja4t", "64240_2-4-8-1-3_1460_7", "https://127.0.0.1/"},
	}
	for _, args := range cases {
		var stdout, stderr bytes.Buffer
		if code := Run(args, &stdout, &stderr, "test"); code != 2 {
			t.Errorf("%v: exit %d: %s", args, code, stderr.String())
		}
	}
}

func TestIPFamilyNarrowsTCPDial(t *testing.T) {
	original := dialContext
	var networks []string
	dialContext = func(_ context.Context, network, _ string) (net.Conn, error) {
		networks = append(networks, network)
		return nil, fmt.Errorf("stop")
	}
	t.Cleanup(func() { dialContext = original })

	for _, args := range [][]string{{"http://127.0.0.1/"}, {"-4", "http://127.0.0.1/"}, {"--ipv6", "http://127.0.0.1/"}} {
		var stdout, stderr bytes.Buffer
		Run(args, &stdout, &stderr, "test")
	}
	if got := strings.Join(networks, ","); got != "tcp,tcp4,tcp6" {
		t.Fatalf("networks = %s", got)
	}
}

func TestIPv6RejectedWithJA4T(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := Run([]string{"-6", "--ja4t", "64240_2-4-8-1-3_1460_7", "http://127.0.0.1/"}, &stdout, &stderr, "test")
	if code != 2 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
}

func TestVersionListsHTTP3(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"-V"}, &stdout, &stderr, "test"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(stdout.String(), "Features: HTTP2 HTTP3\n") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
