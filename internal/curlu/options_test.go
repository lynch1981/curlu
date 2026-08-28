package curlu

import (
	"reflect"
	"sort"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
)

func TestParseArgsExactWorkflow(t *testing.T) {
	opts, err := ParseArgs([]string{
		"-iv", "-H", "User-Agent:", "-HAccept:", "-H", "Host:", "-sS",
		"--connect-timeout", "2.5", "http://127.0.0.1:8080/health", "--max-time=10",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.Include || !opts.Silent || !opts.ShowError || !opts.Verbose {
		t.Fatalf("boolean options not parsed: %+v", opts)
	}
	if opts.ConnectTimeout != 2500*time.Millisecond || opts.MaxTime != 10*time.Second {
		t.Fatalf("timeouts not parsed: %+v", opts)
	}
	if opts.URL != "http://127.0.0.1:8080/health" {
		t.Fatalf("URL = %q", opts.URL)
	}
	wantHeaders := []string{"User-Agent:", "Accept:", "Host:"}
	if !reflect.DeepEqual(opts.Headers, wantHeaders) {
		t.Fatalf("headers = %#v, want %#v", opts.Headers, wantHeaders)
	}
}

func TestParseArgsLastTimeoutWins(t *testing.T) {
	opts, err := ParseArgs([]string{"--connect-timeout=1", "--connect-timeout", "0", "-m1", "-m", "0.125", "https://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.ConnectTimeout != 0 || opts.MaxTime != 125*time.Millisecond {
		t.Fatalf("timeouts = %v, %v", opts.ConnectTimeout, opts.MaxTime)
	}
}

func TestParseArgsUTLSOptions(t *testing.T) {
	opts, err := ParseArgs([]string{
		"--utls-hello", "hellofirefox_105",
		"--utls-hello=HelloChrome_102",
		"--utls-cipher-append", "0x1234",
		"--utls-cipher-append=0x00fF",
		"--utls-info",
		"https://example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.UTLSHello != utls.HelloChrome_102 {
		t.Fatalf("UTLSHello = %#v", opts.UTLSHello)
	}
	if want := []uint16{0x1234, 0x00ff}; !reflect.DeepEqual(opts.UTLSCiphers, want) {
		t.Fatalf("UTLSCiphers = %#v, want %#v", opts.UTLSCiphers, want)
	}
	if !opts.UTLSInfo {
		t.Fatal("UTLSInfo is false")
	}
}

func TestParseArgsTestNginxCurlCommand(t *testing.T) {
	opts, err := ParseArgs([]string{
		"-i", "-H", "User-Agent:", "-H", "Accept:", "-H", "Host:", "-sS",
		"--http2-prior-knowledge", "-k", "--insecure", "-vv",
		"-H", "Host: localhost",
		"--connect-timeout", "3", "--max-time", "3",
		"--utls-hello HelloFirefox_55",
		"https://localhost:1984/t",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.Include || !opts.Silent || !opts.ShowError || !opts.Verbose {
		t.Fatalf("boolean options not parsed: %+v", opts)
	}
	if opts.UTLSHello != utls.HelloFirefox_55 {
		t.Fatalf("UTLSHello = %#v", opts.UTLSHello)
	}
	if opts.URL != "https://localhost:1984/t" {
		t.Fatalf("URL = %q", opts.URL)
	}
}

func TestParseArgsCurlOptionsBlob(t *testing.T) {
	opts, err := ParseArgs([]string{
		"--utls-hello=HelloChrome_120 --utls-cipher-append 0x00ff",
		"https://example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.UTLSHello != utls.HelloChrome_120 {
		t.Fatalf("UTLSHello = %#v", opts.UTLSHello)
	}
	if want := []uint16{0x00ff}; !reflect.DeepEqual(opts.UTLSCiphers, want) {
		t.Fatalf("UTLSCiphers = %#v, want %#v", opts.UTLSCiphers, want)
	}
}

func TestParseArgsUTLSALPN(t *testing.T) {
	opts, err := ParseArgs([]string{
		"--utls-hello", "HelloChrome_120",
		"--utls-alpn-hex", "6820",
		"https://example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.UTLSALPN != "h " {
		t.Fatalf("UTLSALPN = %q", opts.UTLSALPN)
	}
	if opts.UTLSALPNNone {
		t.Fatal("UTLSALPNNone is true")
	}

	opts, err = ParseArgs([]string{"--utls-alpn-none", "--utls-alpn-hex=68", "https://example.test/"})
	if err == nil {
		t.Fatalf("combined ALPN flags unexpectedly succeeded: %+v", opts)
	}

	opts, err = ParseArgs([]string{"--utls-alpn-none", "https://example.test/"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.UTLSALPNNone || opts.UTLSALPN != "" {
		t.Fatalf("none: %+v", opts)
	}

	opts, err = ParseArgs([]string{
		"--utls-hello HelloChrome_120 --utls-alpn-hex 2068",
		"https://example.test/",
	})
	if err != nil {
		t.Fatal(err)
	}
	if opts.UTLSHello != utls.HelloChrome_120 || opts.UTLSALPN != " h" {
		t.Fatalf("blob: hello=%#v alpn=%q", opts.UTLSHello, opts.UTLSALPN)
	}
}

func TestParseArgsUTLSHelloListNeedsNoURL(t *testing.T) {
	opts, err := ParseArgs([]string{"--utls-hello-list"})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.UTLSHelloList {
		t.Fatal("UTLSHelloList is false")
	}
}

func TestUTLSHelloCatalog(t *testing.T) {
	names := utlsHelloNames()
	if len(names) != 49 {
		t.Fatalf("len(names) = %d, want 49", len(names))
	}
	if !sort.StringsAreSorted(names) {
		t.Fatalf("names are not sorted: %q", names)
	}
	seen := make(map[string]bool, len(names))
	for _, name := range names {
		if name == "HelloCustom" || name == "Custom-0" {
			t.Fatalf("%q must not be exposed", name)
		}
		if seen[name] {
			t.Fatalf("duplicate ClientHello ID %q", name)
		}
		seen[name] = true
		if _, canonical, ok := resolveUTLSHello(name); !ok || canonical != name {
			t.Fatalf("resolveUTLSHello(%q) = %q, %v", name, canonical, ok)
		}
	}
	for _, want := range []string{
		"HelloChrome_133", "HelloChrome_Auto", "HelloChrome_106_Shuffle",
		"HelloEdge_106", "HelloGolang", "HelloRandomizedNoALPN",
	} {
		if !seen[want] {
			t.Errorf("catalog missing %q", want)
		}
	}
	for _, name := range []string{"Chrome-102", "Chrome-120", "120", "Golang-0"} {
		if _, _, ok := resolveUTLSHello(name); ok {
			t.Errorf("resolveUTLSHello(%q) unexpectedly succeeded", name)
		}
	}
}

func TestParseArgsErrors(t *testing.T) {
	tests := [][]string{
		{}, {"--unknown", "http://example.test"}, {"-m", "-1", "http://example.test"},
		{"-m", "1m", "http://example.test"}, {"--max-time", "NaN", "http://example.test"},
		{"http://one.test", "http://two.test"}, {"--header"}, {"--utls-hello"},
		{"--utls-hello", "HelloChrome_999", "https://example.test"},
		{"--utls-hello", "Chrome-102", "https://example.test"}, {"--utls-cipher-append"},
		{"--utls-hello-list=yes"}, {"--utls-info=yes", "https://example.test"},
		{"--verbose=yes", "https://example.test"},
		{"--utls-alpn-hex", "https://example.test"}, {"--utls-alpn-hex", "6", "https://example.test"},
		{"--utls-alpn-hex", "zz", "https://example.test"}, {"--utls-alpn-none=yes", "https://example.test"},
		{"--utls-alpn-none", "--utls-alpn-hex", "68", "https://example.test"},
	}
	for _, cipher := range []string{"0x0", "0X1234", "1234", "0x12345", "0xzzzz", "-0x0001"} {
		tests = append(tests, []string{"--utls-cipher-append", cipher, "https://example.test"})
	}
	for _, args := range tests {
		if _, err := ParseArgs(args); err == nil {
			t.Errorf("ParseArgs(%q) unexpectedly succeeded", args)
		}
	}
}

func TestIsGREASE(t *testing.T) {
	for _, value := range []uint16{0x0a0a, 0x1a1a, 0xfafa} {
		if !isGREASE(value) {
			t.Errorf("isGREASE(%#04x) = false", value)
		}
	}
	for _, value := range []uint16{0x0000, 0x00ff, 0x0a1a, 0x1a0a, 0xffff} {
		if isGREASE(value) {
			t.Errorf("isGREASE(%#04x) = true", value)
		}
	}
}

func TestParseSeconds(t *testing.T) {
	d, err := parseSeconds("2.5")
	if err != nil || d != 2500*time.Millisecond {
		t.Fatalf("parseSeconds(2.5) = %v, %v", d, err)
	}
	d, err = parseSeconds("0")
	if err != nil || d != 0 {
		t.Fatalf("parseSeconds(0) = %v, %v", d, err)
	}
	for _, in := range []string{"1m", "1u", "1n", "1h2m3", "NaN", "Inf", "+Inf", "-Inf", "1e20"} {
		if _, err := parseSeconds(in); err == nil {
			t.Errorf("parseSeconds(%q) unexpectedly succeeded", in)
		}
	}
	if _, err := parseSeconds("-1"); err == nil {
		t.Fatal("parseSeconds(-1) unexpectedly succeeded")
	}
}
