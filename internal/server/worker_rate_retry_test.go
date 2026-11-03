package server

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

func TestWorkerRateLimitRetryPreservesPayloadAndRefreshesSignature(t *testing.T) {
	nonces := map[string]bool{}
	attempts := 0
	worker := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		attempts++
		body, _ := io.ReadAll(request.Body)
		if string(body) != `{"content":"test","path":"instance/data/server.properties"}` {
			t.Errorf("unexpected retry body: %s", body)
		}
		if request.Method != http.MethodPost || request.URL.RequestURI() != "/fs/write?mode=test" {
			t.Errorf("unexpected retry target: %s %s", request.Method, request.URL)
		}
		nonce := request.Header.Get("X-Request-Nonce")
		if nonce == "" || nonces[nonce] {
			t.Error("retry reused an authentication nonce")
		}
		nonces[nonce] = true
		wantSignature := signWorkerRequest("key", request.Header.Get("X-Request-Timestamp"), nonce, request.Method, request.URL.RequestURI())
		if request.Header.Get("X-Request-Signature") != wantSignature {
			t.Error("invalid retry signature")
		}
		if attempts < 3 {
			response.Header().Set("Retry-After", "1")
			response.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_, _ = response.Write([]byte("ok"))
	}))
	defer worker.Close()
	baseURL, _ := url.Parse(worker.URL)
	backend := &Server{}
	code, body, err := backend.callWorkerJSON(context.Background(), baseURL, "key", http.MethodPost, "/fs/write?mode=test",
		map[string]string{"path": "instance/data/server.properties", "content": "test"})
	if err != nil || code != http.StatusOK || string(body) != "ok" || attempts != 3 {
		t.Fatalf("code=%d body=%s attempts=%d error=%v", code, body, attempts, err)
	}
}

func TestWorkerRateLimitRetriesAreBoundedAndOtherFailuresAreNotRetried(t *testing.T) {
	for _, statusCode := range []int{http.StatusTooManyRequests, http.StatusForbidden, http.StatusInternalServerError} {
		attempts := 0
		worker := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
			attempts++
			response.WriteHeader(statusCode)
		}))
		baseURL, _ := url.Parse(worker.URL)
		backend := &Server{}
		code, _, err := backend.callWorkerJSON(context.Background(), baseURL, "key", http.MethodPost, "/stack/up", nil)
		worker.Close()
		wantAttempts := 1
		if statusCode == http.StatusTooManyRequests {
			wantAttempts = 3
		}
		if err != nil || code != statusCode || attempts != wantAttempts {
			t.Fatalf("status=%d code=%d attempts=%d error=%v", statusCode, code, attempts, err)
		}
	}
}

func TestWorkerRateLimitWaitHonorsCancellation(t *testing.T) {
	worker := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Retry-After", "30")
		response.WriteHeader(http.StatusTooManyRequests)
	}))
	defer worker.Close()
	baseURL, _ := url.Parse(worker.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	backend := &Server{}
	_, _, err := backend.callWorkerJSON(ctx, baseURL, "key", http.MethodPost, "/fs/write", nil)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("cancellation error = %v", err)
	}
}
