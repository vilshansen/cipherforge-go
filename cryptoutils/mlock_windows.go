//go:build windows

package cryptoutils

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// MlockBytes pins the given byte slice in physical RAM using VirtualLock,
// preventing the OS from swapping it to disk where it could be recovered
// by an attacker with access to the pagefile.
//
// Failure is treated as non-fatal and silently ignored. Callers must still
// zero the slice via ZeroBytes when done.
func MlockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}
