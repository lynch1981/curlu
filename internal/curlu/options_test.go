package curlu

import (
	"reflect"
	"testing"
	"time"
)

func TestParseArgsExactWorkflow(t *testing.T) {
	opts, err := ParseArgs([]string{
		"-i", "-H", "User-Agent:", "-HAccept:", "-H", "Host:", "-sS",
		"--connect-timeout", "2.5", "http://127.0.0.1:8080/health", "--max-time=10",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !opts.Include || !opts.Silent || !opts.ShowError {
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

func TestParseArgsErrors(t *testing.T) {
	tests := [][]string{
		{}, {"--unknown", "http://example.test"}, {"-m", "-1", "http://example.test"},
		{"http://one.test", "http://two.test"}, {"--header"},
	}
	for _, args := range tests {
		if _, err := ParseArgs(args); err == nil {
			t.Errorf("ParseArgs(%q) unexpectedly succeeded", args)
		}
	}
}
