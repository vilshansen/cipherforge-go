package tui

import (
	"bufio"
	"bytes"
	b64 "encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/vilshansen/cipherforge-go/pkg/cipherforge"
)

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
		var result string
		if m.operation == "encrypt" {
			result, err = runTextEncrypt(m.inputText, m.password, ch)
		} else {
			result, err = runTextDecrypt(m.inputText, m.password, ch)
		}
		if err != nil {
			ch <- progressTickMsg{err: err}
		} else {
			ch <- progressTickMsg{done: true, result: result}
		}
		return
	}
	if m.operation == "encrypt" {
		err = runEncrypt(m.inputFile, m.outputFile, m.password, m.base64, ch)
	} else {
		err = runDecrypt(m.inputFile, m.outputFile, m.password, m.base64, ch)
	}
	if err != nil {
		ch <- progressTickMsg{err: err}
	}
}

func runEncrypt(inputFile, outputFile string, password []byte, base64 bool, ch chan<- progressTickMsg) error {
	in, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}
	defer in.Close()

	succeeded := false
	out, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer func() {
		out.Close()
		if !succeeded {
			os.Remove(outputFile)
		}
	}()

	var writer io.Writer = bufio.NewWriterSize(out, 1024*1024)
	bufWriter := writer.(*bufio.Writer)
	var b64Closer io.Closer
	if base64 {
		b64w := b64.NewEncoder(b64.StdEncoding, writer)
		writer = b64w
		b64Closer = b64w
	}

	enc := cipherforge.NewEncrypter(password)
	err = enc.Encrypt(in, writer, func(bytes int64) {
		sendProgress(ch, bytes)
	})

	if b64Closer != nil {
		if closeErr := b64Closer.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}
	if flushErr := bufWriter.Flush(); flushErr != nil && err == nil {
		err = flushErr
	}

	if err == nil {
		succeeded = true
	}
	return err
}

func runDecrypt(inputFile, outputFile string, password []byte, base64 bool, ch chan<- progressTickMsg) error {
	in, err := os.Open(inputFile)
	if err != nil {
		return fmt.Errorf("open input: %w", err)
	}

	var reader io.ReadSeeker = in
	if base64 {
		raw, err := io.ReadAll(in)
		in.Close() // done with file; raw data is in memory
		if err != nil {
			return fmt.Errorf("read base64 input: %w", err)
		}
		decoded := make([]byte, b64.StdEncoding.DecodedLen(len(raw)))
		n, err := b64.StdEncoding.Decode(decoded, raw)
		if err != nil {
			return fmt.Errorf("decode base64: %w", err)
		}
		reader = strings.NewReader(string(decoded[:n]))
	} else {
		defer in.Close()
	}

	succeeded := false
	out, err := os.OpenFile(outputFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open output: %w", err)
	}
	defer func() {
		out.Close()
		if !succeeded {
			os.Remove(outputFile)
		}
	}()

	dec := cipherforge.NewDecrypter(password)
	err = dec.Decrypt(reader, out, func(bytes int64) {
		sendProgress(ch, bytes)
	})

	if err == nil {
		succeeded = true
	}
	return err
}

// sendProgress sends a progress tick. Blocks briefly if the channel is full
// — the encryption goroutine waits for the UI to catch up.
func sendProgress(ch chan<- progressTickMsg, bytes int64) {
	ch <- progressTickMsg{bytes: bytes}
}

// runTextEncrypt encrypts plaintext in memory and writes base64 output to out.
func runTextEncrypt(plaintext string, password []byte, ch chan<- progressTickMsg) (string, error) {
	in := strings.NewReader(plaintext)
	var buf bytes.Buffer

	enc := cipherforge.NewEncrypter(password)
	if err := enc.Encrypt(in, &buf, func(b int64) { sendProgress(ch, b) }); err != nil {
		return "", err
	}

	var b64buf bytes.Buffer
	b64w := b64.NewEncoder(b64.StdEncoding, &b64buf)
	if _, err := b64w.Write(buf.Bytes()); err != nil {
		return "", err
	}
	b64w.Close()
	return b64buf.String(), nil
}

func runTextDecrypt(b64input string, password []byte, ch chan<- progressTickMsg) (string, error) {
	raw, err := b64.StdEncoding.DecodeString(b64input)
	if err != nil {
		return "", fmt.Errorf("invalid base64 input: %w", err)
	}

	in := bytes.NewReader(raw)
	var buf bytes.Buffer

	dec := cipherforge.NewDecrypter(password)
	if err := dec.Decrypt(in, &buf, func(b int64) { sendProgress(ch, b) }); err != nil {
		return "", err
	}
	return buf.String(), nil
}
