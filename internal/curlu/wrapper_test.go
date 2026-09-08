package curlu

import (
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

func TestCurlWrapperSyntax(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller")
	}
	script := filepath.Join(filepath.Dir(file), "..", "..", "curl")
	out, err := exec.Command("bash", "-n", script).CombinedOutput()
	if err != nil {
		t.Fatalf("bash -n %s: %v\n%s", script, err, out)
	}
}
