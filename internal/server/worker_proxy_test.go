package server

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestBufferUploadBodyEnforcesSizeLimit(t *testing.T) {
	tmp, size, err := bufferUploadBody(strings.NewReader("123456"), 5)
	if tmp != nil {
		name := tmp.Name()
		_ = tmp.Close()
		_ = os.Remove(name)
	}
	if err != errWorkerUploadTooLarge {
		t.Fatalf("expected oversized upload error, got %v", err)
	}
	if size != 6 {
		t.Fatalf("expected size to report the first byte over the limit, got %d", size)
	}
}

func TestBufferUploadBodyAllowsBodyAtSizeLimit(t *testing.T) {
	tmp, size, err := bufferUploadBody(strings.NewReader("12345"), 5)
	if err != nil {
		t.Fatalf("expected upload at limit to be accepted, got %v", err)
	}
	defer func() {
		name := tmp.Name()
		_ = tmp.Close()
		_ = os.Remove(name)
	}()

	if size != 5 {
		t.Fatalf("expected size 5, got %d", size)
	}
	body, err := io.ReadAll(tmp)
	if err != nil {
		t.Fatalf("failed to read buffered upload: %v", err)
	}
	if string(body) != "12345" {
		t.Fatalf("unexpected buffered body %q", body)
	}
}
