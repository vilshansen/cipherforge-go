// Package publish moves a fully written staging file into place at its final
// path, refusing to replace an existing destination unless the caller asked for
// it.
//
// Both front ends stage their output in a temporary file and move it into place
// only after the whole operation has succeeded, so an interrupted run never
// leaves a partial file at the destination. This package is that final step.
//
// It exists so the CLI and the TUI cannot drift apart on the overwrite rule:
// the CLI re-checked the destination before publishing while the TUI published
// with a bare os.Rename and no check at all.
package publish

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// ErrExists reports that the destination exists and force was not requested.
// Callers branch on it to produce their own user-facing wording, because the
// remedy differs: the CLI points at -f, the TUI has no such flag.
var ErrExists = errors.New("destination exists and force was not requested")

// Publish moves stagingPath to destPath, atomically when both are on the same
// filesystem.
//
// With force false the destination must not exist, so a file that appeared while
// the operation was running is left untouched instead of being replaced. The
// check happens here, immediately before the move, rather than only at the start
// of the operation: the caller committed to publishing long before it gets here,
// and noticing a file that appeared in between is the entire point.
//
// The check and the move remain two operations, so this narrows the window to
// microseconds rather than closing it. Closing it needs an atomic "rename only
// if absent", which os does not expose portably: Linux has
// renameat2(RENAME_NOREPLACE) and Windows has ReplaceFile, and a hard-link trick
// (os.Link then remove) fails outright on filesystems without hard links. For a
// tool that must work on any local filesystem that trade is not worth it — an
// attacker able to create files in the destination directory can already replace
// the output directly, so what remains is a data-loss hazard for an unlucky
// legitimate file rather than a way to defeat a security control.
//
// With force true the destination is replaced unconditionally, which is what an
// explicit -f on the CLI or a confirmed overwrite in the TUI means.
func Publish(stagingPath, destPath string, force bool) error {
	if !force {
		// Lstat, not Stat: a dangling symlink at destPath still means something
		// is there, and renaming over it would destroy an artifact the user
		// created — the same class of loss this check exists to prevent.
		if _, err := os.Lstat(destPath); err == nil {
			return fmt.Errorf("%w: %s", ErrExists, destPath)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("checking %s: %w", destPath, err)
		}
	}

	// os.Rename is atomic when src and dst are on the same filesystem, which is
	// why callers stage in the destination directory.
	if err := os.Rename(stagingPath, destPath); err != nil {
		return fmt.Errorf("atomic rename failed: %w", err)
	}
	return nil
}
