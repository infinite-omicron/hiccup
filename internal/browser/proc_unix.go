//go:build !windows

package browser

import (
	"os/exec"
	"syscall"
)

// detach starts the browser in its own session so it outlives hiccup.
func detach(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }

func alive(pid int) bool { return pid > 0 && syscall.Kill(pid, 0) == nil }

// kill ends the browser's whole process group (it was started as a session leader).
func kill(pid int) { _ = syscall.Kill(-pid, syscall.SIGTERM) }
