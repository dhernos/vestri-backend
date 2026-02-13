package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// RotatingFileWriter writes logs into a file and rotates old content
// when a size limit is reached.
type RotatingFileWriter struct {
	mu           sync.Mutex
	path         string
	maxSizeBytes int64
	maxBackups   int
	file         *os.File
	size         int64
}

func NewRotatingFileWriter(path string, maxSizeBytes int64, maxBackups int) (*RotatingFileWriter, error) {
	if path == "" {
		return nil, fmt.Errorf("log path is required")
	}
	if maxSizeBytes <= 0 {
		return nil, fmt.Errorf("maxSizeBytes must be > 0")
	}
	if maxBackups < 0 {
		maxBackups = 0
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}

	var size int64
	if stat, err := f.Stat(); err == nil {
		size = stat.Size()
	}

	w := &RotatingFileWriter{
		path:         path,
		maxSizeBytes: maxSizeBytes,
		maxBackups:   maxBackups,
		file:         f,
		size:         size,
	}

	// If the file is already oversized at startup, rotate immediately.
	if w.size > w.maxSizeBytes {
		if err := w.rotateLocked(); err != nil {
			return nil, err
		}
	}

	return w, nil
}

func (w *RotatingFileWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return 0, os.ErrClosed
	}

	// Avoid rotating forever for one oversized line by allowing one write
	// into an empty file.
	if w.size > 0 && w.size+int64(len(p)) > w.maxSizeBytes {
		if err := w.rotateLocked(); err != nil {
			return 0, err
		}
	}

	n, err := w.file.Write(p)
	w.size += int64(n)
	return n, err
}

func (w *RotatingFileWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}

func (w *RotatingFileWriter) rotateLocked() error {
	if w.file != nil {
		if err := w.file.Close(); err != nil {
			return err
		}
		w.file = nil
	}

	if w.maxBackups <= 0 {
		if err := os.Remove(w.path); err != nil && !os.IsNotExist(err) {
			return err
		}
	} else {
		if err := shiftBackups(w.path, w.maxBackups); err != nil {
			return err
		}
	}

	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}

	w.file = f
	w.size = 0
	return nil
}

func shiftBackups(basePath string, maxBackups int) error {
	oldestPath := backupPath(basePath, maxBackups)
	if err := os.Remove(oldestPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	for idx := maxBackups - 1; idx >= 1; idx-- {
		src := backupPath(basePath, idx)
		if _, err := os.Stat(src); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}

		dst := backupPath(basePath, idx+1)
		if err := os.Remove(dst); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Rename(src, dst); err != nil {
			return err
		}
	}

	if _, err := os.Stat(basePath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}

	firstBackup := backupPath(basePath, 1)
	if err := os.Remove(firstBackup); err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Rename(basePath, firstBackup)
}

func backupPath(basePath string, idx int) string {
	return fmt.Sprintf("%s.%d", basePath, idx)
}
