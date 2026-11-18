// Package opener opens files in the desktop app that handles them,
// preferring Microsoft Excel for workbooks.
package opener

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Command returns the command that opens path: Microsoft Excel for
// .xlsx/.xltx files when it's installed, otherwise the default app.
func Command(path string) *exec.Cmd {
	workbook := strings.EqualFold(filepath.Ext(path), ".xlsx") || strings.EqualFold(filepath.Ext(path), ".xltx")
	switch runtime.GOOS {
	case "darwin":
		if workbook && excelInstalled() {
			return exec.Command("open", "-a", "Microsoft Excel", path)
		}
		return exec.Command("open", path)
	case "windows":
		// Uses the registered handler, which is Excel when it's installed.
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", path)
	default:
		return exec.Command("xdg-open", path)
	}
}

func excelInstalled() bool {
	for _, dir := range []string{"/Applications", filepath.Join(os.Getenv("HOME"), "Applications")} {
		if _, err := os.Stat(filepath.Join(dir, "Microsoft Excel.app")); err == nil {
			return true
		}
	}
	return false
}

// handoff bounds how long Open waits for the launcher to hand the file over.
const handoff = 10 * time.Second

// Open opens path in its app. It waits for the launcher (open, xdg-open,
// rundll32) to hand the file over, which takes a moment when the app is still
// starting; if hiccup exited first, the launcher could be cleaned up with it and
// the app would start without the file. It does not wait for the app to exit.
func Open(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cmd := Command(abs)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open %s: %w", abs, err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			return fmt.Errorf("open %s: %w", abs, err)
		}
	case <-time.After(handoff):
		// Some launchers stay until the app exits; the file is open by now.
	}
	return nil
}

// InUse reports whether a spreadsheet app has path open, going by the lock
// files LibreOffice (".~lock.<name>#") and Microsoft Excel ("~$<name>")
// keep next to documents they have open.
func InUse(path string) bool {
	dir, name := filepath.Dir(path), filepath.Base(path)
	for _, lock := range []string{".~lock." + name + "#", "~$" + name} {
		if _, err := os.Stat(filepath.Join(dir, lock)); err == nil {
			return true
		}
	}
	return false
}
