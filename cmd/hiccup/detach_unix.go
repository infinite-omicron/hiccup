//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// detach starts the process in its own session so it outlives hiccup.
func detach(c *exec.Cmd) { c.SysProcAttr = &syscall.SysProcAttr{Setsid: true} }
