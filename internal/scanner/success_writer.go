package scanner

import (
	"encoding/csv"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"sync"
)

type successWriter struct {
	mu    sync.Mutex
	file  *os.File
	count int
}

type successCSVWriter struct {
	mu     sync.Mutex
	file   *os.File
	writer *csv.Writer
}

func newSuccessWriter(path string) (*successWriter, error) {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}

	return &successWriter{
		file: file,
	}, nil
}

func (w *successWriter) Append(line string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return errors.New("success writer is closed")
	}

	if w.count > 0 {
		if _, err := w.file.WriteString("\n"); err != nil {
			return err
		}
	}

	if _, err := w.file.WriteString(line); err != nil {
		return err
	}

	if err := w.file.Sync(); err != nil {
		return err
	}

	w.count++
	return nil
}

func (w *successWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}

	err := w.file.Close()
	w.file = nil
	return err
}

func newSuccessCSVWriter(path string) (*successCSVWriter, error) {
	dir := filepath.Dir(path)
	if dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, err
		}
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return nil, err
	}

	writer := csv.NewWriter(file)
	header := []string{
		"ip",
		"ping_ok",
		"probe_pattern",
		"success_count",
		"total_queries",
		"ping_ms",
		"avg_dns_ms",
		"status",
		"reason",
	}
	if err := writer.Write(header); err != nil {
		_ = file.Close()
		return nil, err
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		_ = file.Close()
		return nil, err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return nil, err
	}

	return &successCSVWriter{
		file:   file,
		writer: writer,
	}, nil
}

func (w *successCSVWriter) Append(row []string) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil || w.writer == nil {
		return errors.New("success csv writer is closed")
	}

	if err := w.writer.Write(row); err != nil {
		return err
	}
	w.writer.Flush()
	if err := w.writer.Error(); err != nil {
		return err
	}
	return w.file.Sync()
}

func (w *successCSVWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.writer != nil {
		w.writer.Flush()
		if err := w.writer.Error(); err != nil {
			_ = w.file.Close()
			w.writer = nil
			w.file = nil
			return err
		}
	}

	if w.file == nil {
		w.writer = nil
		return nil
	}

	err := w.file.Close()
	w.file = nil
	w.writer = nil
	return err
}

func detailCSVRow(
	ip string,
	pingOK bool,
	probePattern string,
	successCount int,
	totalQueries int,
	pingMS int64,
	avgDNSMS int64,
	status string,
	reason string,
) []string {
	pingStr := "N"
	if pingOK {
		pingStr = "Y"
	}

	return []string{
		ip,
		pingStr,
		probePattern,
		strconv.Itoa(successCount),
		strconv.Itoa(totalQueries),
		strconv.FormatInt(pingMS, 10),
		strconv.FormatInt(avgDNSMS, 10),
		status,
		reason,
	}
}
