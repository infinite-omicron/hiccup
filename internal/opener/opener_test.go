package opener

import (
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
