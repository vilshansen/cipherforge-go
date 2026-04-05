//go:build !windows

package cryptoutils

import "golang.org/x/sys/unix"

// MlockBytes pins the given byte slice in physical RAM using mlock(2),
// preventing the OS from swapping it to disk where it could be recovered
// by an attacker with access to the swap partition or hibernation file.
//
// Failure is treated as non-fatal and silently ignored: mlock may be
// unavailable in sandboxed environments, containers with low RLIMIT_MEMLOCK,
// or on platforms that do not support it. Callers must still zero the slice
// via ZeroBytes when done.
func MlockBytes(b []byte) {
	_ = unix.Mlock(b)
}
