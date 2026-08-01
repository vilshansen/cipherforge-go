// Go build constraint: this file is only compiled on Windows.
// See mlock_unix.go for the Unix/Linux/macOS implementation and an
// explanation of Go's build tag system.
//
//go:build windows

package crypto

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// MlockBytes pins the given byte slice in physical RAM using VirtualLock,
// preventing the OS from swapping it to disk where it could be recovered
// by an attacker with access to the pagefile.
//
// VirtualLock is the Windows equivalent of Unix mlock(2). Unlike mlock,
// VirtualLock operates on pages — the entire page containing each byte
// is locked. There is no per-page limit on Windows (unlike RLIMIT_MEMLOCK
// on Linux), but VirtualLock still requires the SeLockMemoryPrivilege
// privilege, which is not granted by default. Failure is non-fatal.
//
// Note the `unsafe.Pointer` usage: this is Go's escape hatch for raw
// pointer manipulation (like Java's sun.misc.Unsafe). Unlike Java, where
// Unsafe is discouraged and may be removed, Go's unsafe package is a
// supported (if dangerous) part of the language — it's the only way to
// get a raw memory address from a slice. The pattern:
//
//	unsafe.Pointer(&b[0])  // address of the first byte of the backing array
//
// is the canonical way to pass a Go slice to a C-like API that expects
// a void* pointer. The &b[0] syntax takes the address of the first element
// (safe because len > 0 is checked first). uintptr converts the pointer to
// an integer for the Windows API call.
func MlockBytes(b []byte) {
	if len(b) == 0 {
		return
	}
	_ = windows.VirtualLock(uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)))
}
