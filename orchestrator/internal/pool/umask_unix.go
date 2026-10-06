package pool

import "syscall"

// setUmask sets the process file-creation mask and returns the previous value.
//
// syscall.Umask is the stdlib way to do this. The golang.org/x/sys/unix package
// would also work, but importing it for a single call would be the first
// third-party dependency in a component whose audit surface is the argument for
// it existing (PLANNING/PLAN-v3.md §2.1, orchestrator/README.md#language-go).
//
// Only meaningful on Unix. The file name ends in _unix so a build for another
// platform fails to compile here rather than silently reporting a umask that
// was never applied.
func setUmask(mask int) int { return syscall.Umask(mask) }
