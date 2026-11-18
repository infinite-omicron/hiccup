package opener

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

func TestCommandOpensThePath(t *testing.T) {
	cmd := Command("/tmp/acme-auth-matrix.xlsx")
	if !slices.Contains(cmd.Args, "/tmp/acme-auth-matrix.xlsx") {
		t.Errorf("args %v don't include the file", cmd.Args)
	}
	if runtime.GOOS == "darwin" && excelInstalled() && !slices.Contains(cmd.Args, "Microsoft Excel") {
		t.Errorf("Excel is installed but not chosen: %v", cmd.Args)
	}
	if other := Command("/tmp/notes.txt"); slices.Contains(other.Args, "Microsoft Excel") {
		t.Errorf("non-workbooks should use the default app: %v", other.Args)
	}
}

func TestInUse(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "acme-auth-matrix.xlsx")
	if InUse(path) {
		t.Fatal("no lock file yet")
	}
	for _, lock := range []string{".~lock.acme-auth-matrix.xlsx#", "~$acme-auth-matrix.xlsx"} {
		p := filepath.Join(dir, lock)
		if err := os.WriteFile(p, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		if !InUse(path) {
			t.Errorf("%s should mark the workbook as open", lock)
		}
		_ = os.Remove(p)
	}
}
