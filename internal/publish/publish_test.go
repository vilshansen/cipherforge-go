package publish

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// TestPublishMovesStagingFileIntoPlace covers the happy path: the staged file
// becomes the destination and is no longer present under its staging name.
func TestPublishMovesStagingFileIntoPlace(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	dest := filepath.Join(dir, "dest")

	if err := os.WriteFile(staging, []byte("new content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Publish(staging, dest, false); err != nil {
		t.Fatalf("Publish = %v, want success", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "new content" {
		t.Errorf("dest = %q, want the staged content", got)
	}
	if _, err := os.Lstat(staging); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("staging file still present after publish (err = %v)", err)
	}
}

// TestPublishRefusesToClobberExistingFile is the shared CF-2026-04 / CF-2026-05
// regression test. Callers check the destination at the start of a potentially
// long operation, so a file that appears before the move must not be replaced.
func TestPublishRefusesToClobberExistingFile(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	dest := filepath.Join(dir, "dest")

	if err := os.WriteFile(staging, []byte("new content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("existing content"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := Publish(staging, dest, false)
	if !errors.Is(err, ErrExists) {
		t.Fatalf("Publish = %v, want ErrExists so callers can word their own message", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "existing content" {
		t.Errorf("destination was modified: %q", got)
	}
	// The staging file is deliberately left for the caller to clean up, so it
	// must still be intact rather than half-moved.
	if got, _ := os.ReadFile(staging); string(got) != "new content" {
		t.Errorf("staging file = %q, want it left intact", got)
	}
}

// TestPublishForceReplacesExistingFile covers the consented case: -f on the CLI,
// or a confirmed overwrite in the TUI.
func TestPublishForceReplacesExistingFile(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	dest := filepath.Join(dir, "dest")

	if err := os.WriteFile(staging, []byte("new content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, []byte("existing content"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := Publish(staging, dest, true); err != nil {
		t.Fatalf("Publish with force = %v, want success", err)
	}
	if got, _ := os.ReadFile(dest); string(got) != "new content" {
		t.Errorf("dest = %q, want the staged content", got)
	}
}

// TestPublishRefusesDanglingSymlink pins the Lstat choice: a symlink whose
// target does not exist is still an artifact the user created, so it must not be
// silently replaced by a plain rename.
func TestPublishRefusesDanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	dest := filepath.Join(dir, "dest")

	if err := os.WriteFile(staging, []byte("new content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "missing-target"), dest); err != nil {
		t.Skipf("symlinks unavailable on this system: %v", err)
	}

	if err := Publish(staging, dest, false); !errors.Is(err, ErrExists) {
		t.Fatalf("Publish = %v, want ErrExists for a dangling symlink", err)
	}
	// The symlink must survive, pointing where it did before.
	if target, err := os.Readlink(dest); err != nil {
		t.Errorf("symlink was destroyed by the publish: %v", err)
	} else if filepath.Base(target) != "missing-target" {
		t.Errorf("symlink target = %q, want the original", target)
	}

	// force still replaces it, as an explicit overwrite asks for.
	if err := Publish(staging, dest, true); err != nil {
		t.Fatalf("Publish with force = %v, want success", err)
	}
	if fi, err := os.Lstat(dest); err != nil {
		t.Fatal(err)
	} else if fi.Mode()&fs.ModeSymlink != 0 {
		t.Error("force did not replace the symlink")
	}
}

// TestPublishReportsNonExistenceErrors guards the distinction between "the
// destination is there" and "the check itself could not be completed": the
// latter must not be reported as ErrExists, or callers would tell the user to
// use -f for a problem that -f cannot fix.
func TestPublishReportsNonExistenceErrors(t *testing.T) {
	dir := t.TempDir()
	staging := filepath.Join(dir, "staging")
	if err := os.WriteFile(staging, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}

	// A path whose parent component is a file, not a directory: Lstat fails with
	// ENOTDIR rather than ErrNotExist on every supported platform.
	notADir := filepath.Join(staging, "sub", "dest")
	err := Publish(staging, notADir, false)
	if err == nil {
		t.Fatal("Publish = nil, want an error")
	}
	if errors.Is(err, ErrExists) {
		t.Errorf("Publish = %v, must not be reported as ErrExists", err)
	}
}
