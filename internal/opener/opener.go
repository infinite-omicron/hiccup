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

// Open opens path without waiting for the app to exit.
func Open(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cmd := Command(abs)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("open %s: %w", abs, err)
	}
	go func() { _ = cmd.Wait() }()
	return nil
}
