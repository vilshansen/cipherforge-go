// Go build constraint: this file is only compiled on non-Windows platforms
// (Linux, macOS, FreeBSD, etc.). The opposite file (mlock_windows.go) has
// `//go:build windows` and provides the Windows implementation.
//
// This is Go's conditional compilation mechanism — similar to:
//   - C's #ifndef _WIN32 / #ifdef _WIN32
//   - Rust's #[cfg(not(windows))] / #[cfg(windows)]
//   - Java doesn't have a direct equivalent; you'd use different META-INF
//     or runtime OS checks with System.getProperty("os.name").
//
// Both files MUST define exactly the same exported functions with the same
// signatures, or the build fails with "undefined: MlockBytes".
//
//go:build !windows

package crypto

import "golang.org/x/sys/unix"

// MlockBytes pins the given byte slice in physical RAM using mlock(2),
// preventing the OS from swapping it to disk where it could be recovered
// by an attacker with access to the swap partition or hibernation file.
//
// The underscore assignment `_ = unix.Mlock(b)` discards the error return.
// This is intentional: mlock may fail in sandboxed environments, containers
// with low RLIMIT_MEMLOCK, or platforms that don't support it. We treat
// failure as non-fatal — the keys are still zeroed via ZeroBytes() after use.
// The mlock is a defense-in-depth measure, not a critical security boundary.
//
// Java equivalent: There is no pure-Java equivalent. You would need JNI/JNA
// to call mlock(2). Even then, Java's GC moves objects, so you'd need to
// allocate keys in off-heap ByteBuffer.allocateDirect() and then lock that
// memory. This is one reason the Cipherforge team chose Go over Java for
// this tool: Go gives more control over memory layout.
func MlockBytes(b []byte) {
	_ = unix.Mlock(b)
}
