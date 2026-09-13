package tui

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vilshansen/cipherforge-go/internal/armor"
	"github.com/vilshansen/cipherforge-go/internal/crypto"
	"github.com/vilshansen/cipherforge-go/internal/publish"
	"github.com/vilshansen/cipherforge-go/pkg/cipherforge"
)

// publishOutput moves the staged output into place and translates the shared
// publish.ErrExists into wording that makes sense without a -f flag. The check
// inside publish.Publish runs immediately before the move, so a file that
// appeared at the output path while the operation was running is left alone
// instead of replacing work the user never agreed to lose.
func publishOutput(writePath, outputFile string, force bool) error {
	err := publish.Publish(writePath, outputFile, force)
	if errors.Is(err, publish.ErrExists) {
		return fmt.Errorf("output file %q appeared while processing, so it was left untouched and nothing was written", outputFile)
	}
	return err
}

// barStyle colours the filled portion of the progress bar — matches password box.
var barStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("226"))

// ProgressModel shows live progress during encryption/decryption.
// It receives progressTickMsg updates from the worker goroutine via a channel
// and renders a progress bar with bytes processed and elapsed time.
type ProgressModel struct {
	operation      string
	inputFile      string
	outputFile     string
	bytesProcessed int64
	totalBytes     int64
	startTime      time.Time
	width          int
	height         int
}

func NewProgressModel(operation, inputFile, outputFile string) ProgressModel {
	fi, _ := os.Stat(inputFile)
	var total int64
	if fi != nil {
		total = fi.Size()
	}
	return ProgressModel{
		operation:  operation,
		inputFile:  inputFile,
		outputFile: outputFile,
		totalBytes: total,
		startTime:  time.Now(),
	}
}

func (m *ProgressModel) SetSize(w, h int) { m.width, m.height = w, h }
func (m ProgressModel) Init() tea.Cmd     { return nil }

func (m ProgressModel) View() string {
	var b strings.Builder

	b.WriteString(titleStyle.Render(fmt.Sprintf("%s — In Progress", strings.Title(m.operation))))
	b.WriteString("\n\n")
	b.WriteString(fmt.Sprintf("    Input:   %s\n", m.inputFile))
	b.WriteString(fmt.Sprintf("    Output:  %s\n", m.outputFile))
	b.WriteString("\n")

	elapsed := time.Since(m.startTime).Round(time.Second)
	mb := float64(m.bytesProcessed) / (1024 * 1024)
	speed := "-"
	if elapsed.Seconds() > 0 {
		speed = fmt.Sprintf("%.1f MB/s", mb/elapsed.Seconds())
	}

	barWidth := 40
	filled := 0
	if m.totalBytes > 0 {
		pct := float64(m.bytesProcessed) / float64(m.totalBytes)
		if pct > 1 {
			pct = 1
		}
		filled = int(pct * float64(barWidth))
	}
	bar := barStyle.Render(strings.Repeat("█", filled)) + strings.Repeat("░", barWidth-filled)

	b.WriteString(fmt.Sprintf("    [%s]  %.0f%%\n", bar, float64(filled)*100/float64(barWidth)))
	b.WriteString(fmt.Sprintf("    %.2f MB  |  %s  |  %s\n", mb, speed, elapsed))
	b.WriteString("\n")
	b.WriteString(subtleStyle.Render("Processing..."))

	return b.String()
}

// updateProgress: all real work is driven by progressTickMsg, handled in Model.Update.
func (m Model) updateProgress(msg tea.Msg) (tea.Model, tea.Cmd) {
	return m, nil
}

// runOperation performs the actual encryption or decryption in a goroutine.
func runOperation(m Model, ch chan<- progressTickMsg) {
	defer close(ch)

	var err error
	if m.textMode {
		var result, corrected string
		if m.operation == "encrypt" {
			result, err = runTextEncrypt(m.inputText, m.password, ch)
		} else {
			result, corrected, err = runTextDecrypt(m.inputText, m.password, ch)
		}
		if err != nil {
			ch <- progressTickMsg{err: err}
		} else {
			ch <- progressTickMsg{done: true, result: result, correctedSecret: corrected}
		}
		return
	}
	if m.operation == "encrypt" {
		err = runEncrypt(m.inputFile, m.outputFile, m.password, m.base64, m.forceOverwrite, ch)
	} else {
		var corrected string
		corrected, err = runDecrypt(m.inputFile, m.outputFile, m.password, m.base64, m.forceOverwrite, ch)
		if err == nil {
			// Report a correction so the results screen can show it. A plain
			// success without a correction is signalled by closing the channel.
			ch <- progressTickMsg{done: true, correctedSecret: corrected}
			return
		}
	}
	if err != nil {
		ch <- progressTickMsg{err: err}
	}
}

func runEncrypt(inputFile, outputFile string, password []byte, base64, force bool, ch chan<- progressTickMsg) error {
	in, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	// Write to a temporary file in the destination directory and move it into
	// place on success, so a failed or interrupted encryption never leaves a
	// partial output file at the final path.
	succeeded := false
	out, err := os.CreateTemp(filepath.Dir(outputFile), ".cfo-encrypt-*")
	if err != nil {
		return fmt.Errorf("create temp output: %w", err)
	}
	writePath := out.Name()
	defer func() {
		out.Close()
		if !succeeded {
			os.Remove(writePath)
		}
	}()

	var writer io.Writer = bufio.NewWriterSize(out, 1024*1024)
	bufWriter := writer.(*bufio.Writer)
	var armorCloser io.WriteCloser
	if base64 {
		armorCloser = armor.EncodeWriter(bufWriter)
		writer = armorCloser
	}

	enc := cipherforge.NewEncrypter(password)
	err = enc.Encrypt(in, writer, func(bytes int64) {
		sendProgress(ch, bytes)
	})

	if armorCloser != nil {
		if closeErr := armorCloser.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}
	if flushErr := bufWriter.Flush(); flushErr != nil && err == nil {
		err = flushErr
	}

	if err == nil {
		succeeded = true
		// Close before publishing: the rename reads the file back, and Windows
		// will not rename a file that is still open.
		out.Close()
		if rerr := publishOutput(writePath, outputFile, force); rerr != nil {
			os.Remove(writePath)
			return rerr
		}
	}
	return err
}

func runDecrypt(inputFile, outputFile string, password []byte, base64, force bool, ch chan<- progressTickMsg) (string, error) {
	in, err := os.Open(inputFile)
	if err != nil {
		return "", fmt.Errorf("open input: %w", err)
	}

	var reader io.ReadSeeker = in
	if base64 {
		raw, err := io.ReadAll(in)
		in.Close() // done with file; raw data is in memory
		if err != nil {
			return "", fmt.Errorf("read base64 input: %w", err)
		}
		decoded, err := armor.DecodeBytes(raw)
		if err != nil {
			return "", fmt.Errorf("decode base64: %w", err)
		}
		reader = bytes.NewReader(decoded)
	} else {
		defer in.Close()
	}

	// Always write to a temporary file in the destination directory and
	// atomically rename it into place on success, so a failed or interrupted
	// decryption never leaves partial plaintext at the final path.
	succeeded := false
	out, err := os.CreateTemp(filepath.Dir(outputFile), ".cfo-decrypt-*")
	if err != nil {
		return "", fmt.Errorf("create temp output: %w", err)
	}
	writePath := out.Name()
	defer func() {
		out.Close()
		if !succeeded {
			os.Remove(writePath)
		}
	}()

	dec := cipherforge.NewDecrypter(password)
	err = dec.Decrypt(reader, out, func(bytes int64) {
		sendProgress(ch, bytes)
	})

	// A mistyped secret is the most likely cause of an authentication failure,
	// and the trailer's key-commitment tag lets us test nearby variants without
	// reading the payload. See pkg/cipherforge/repair.go.
	corrected := ""
	if err != nil && cipherforge.IsSecretError(err) {
		if repaired, rerr := cipherforge.RepairSecret(reader, password); rerr == nil {
			// The repaired secret is a real secret: wipe the slice as soon as it
			// has been copied into the string the caller reports, exactly as the
			// CLI does with defer crypto.ZeroBytes(corrected). The deferred call
			// runs after the retry below, so the Decrypter still sees valid bytes.
			defer crypto.ZeroBytes(repaired)
			// Rewind the ciphertext and drop the partial plaintext so the retry
			// starts from a clean state.
			if _, serr := reader.Seek(0, io.SeekStart); serr == nil && out.Truncate(0) == nil {
				if _, serr := out.Seek(0, io.SeekStart); serr == nil {
					dec = cipherforge.NewDecrypter(repaired)
					derr := dec.Decrypt(reader, out, func(bytes int64) {
						sendProgress(ch, bytes)
					})
					if derr == nil {
						corrected = string(repaired)
						err = nil
					} else {
						err = derr
					}
				}
			}
		}
	}

	if err == nil {
		succeeded = true
		// Close before publishing: the rename reads the file back, and Windows
		// will not rename a file that is still open.
		out.Close()
		if rerr := publishOutput(writePath, outputFile, force); rerr != nil {
			os.Remove(writePath)
			return corrected, rerr
		}
	}
	return corrected, err
}

// sendProgress sends a progress tick. Blocks briefly if the channel is full
// — the encryption goroutine waits for the UI to catch up.
func sendProgress(ch chan<- progressTickMsg, bytes int64) {
	ch <- progressTickMsg{bytes: bytes}
}

// runTextEncrypt encrypts plaintext in memory and writes armored base64 output to out.
func runTextEncrypt(plaintext string, password []byte, ch chan<- progressTickMsg) (string, error) {
	in := strings.NewReader(plaintext)
	var buf bytes.Buffer

	enc := cipherforge.NewEncrypter(password)
	if err := enc.Encrypt(in, &buf, func(b int64) { sendProgress(ch, b) }); err != nil {
		return "", err
	}

	return armor.EncodeBytes(buf.Bytes())
}

func runTextDecrypt(b64input string, password []byte, ch chan<- progressTickMsg) (string, string, error) {
	raw, err := armor.DecodeString(b64input)
	if err != nil {
		return "", "", fmt.Errorf("invalid base64 input: %w", err)
	}

	in := bytes.NewReader(raw)
	var buf bytes.Buffer

	dec := cipherforge.NewDecrypter(password)
	err = dec.Decrypt(in, &buf, func(b int64) { sendProgress(ch, b) })

	// Mirror the file path: a mistyped secret can be corrected from the key
	// commitment, which needs no payload decryption.
	corrected := ""
	if err != nil && cipherforge.IsSecretError(err) {
		if repaired, rerr := cipherforge.RepairSecret(in, password); rerr == nil {
			// Mirrors the file path above: wipe the repaired secret once it has
			// been copied out, as the CLI does.
			defer crypto.ZeroBytes(repaired)
			if _, serr := in.Seek(0, io.SeekStart); serr == nil {
				buf.Reset()
				dec = cipherforge.NewDecrypter(repaired)
				if derr := dec.Decrypt(in, &buf, func(b int64) { sendProgress(ch, b) }); derr == nil {
					corrected = string(repaired)
					err = nil
				} else {
					err = derr
				}
			}
		}
	}

	if err != nil {
		return "", "", err
	}
	return buf.String(), corrected, nil
}
