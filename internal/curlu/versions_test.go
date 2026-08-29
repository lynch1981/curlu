package curlu

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

func TestPinnedVersions(t *testing.T) {
	if got := runtimeGoVersion(); got != PinnedGoVersion {
		t.Errorf("runtime Go version = %q, want %q; JA4 fingerprints require this exact toolchain", got, PinnedGoVersion)
	}

	root := moduleRoot(t)
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	goLine := "go " + strings.TrimPrefix(PinnedGoVersion, "go")
	if !bytes.Contains(mod, []byte("\n"+goLine+"\n")) {
		t.Errorf("go.mod missing %q", goLine)
	}
	if !bytes.Contains(mod, []byte(pinnedUTLSModule+" "+PinnedUTLSVersion)) {
		t.Errorf("go.mod must require %s %s", pinnedUTLSModule, PinnedUTLSVersion)
	}
	if regexp.MustCompile(`(?m)^replace\s`).Match(mod) {
		t.Error("go.mod must not replace modules; JA4 pins require the released uTLS zip")
	}

	bin := filepath.Join(t.TempDir(), "curlu")
	build := exec.Command("go", "build", "-o", bin, "./cmd/curlu")
	build.Dir = root
	build.Env = append(os.Environ(), "GOTOOLCHAIN="+PinnedGoVersion)
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	out, err := exec.Command(bin, "-V").Output()
	if err != nil {
		t.Fatalf("curlu -V: %v", err)
	}
	got := string(out)
	if !strings.Contains(got, "uTLS "+PinnedUTLSVersion) {
		t.Errorf("curlu -V missing uTLS %s:\n%s", PinnedUTLSVersion, got)
	}
	if !strings.Contains(got, PinnedGoVersion) {
		t.Errorf("curlu -V missing %s:\n%s", PinnedGoVersion, got)
	}
	if want := "Protocols: http https\n"; !strings.HasSuffix(got, want) {
		t.Errorf("curlu -V = %q, want suffix %q", got, want)
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found")
		}
		dir = parent
	}
}
