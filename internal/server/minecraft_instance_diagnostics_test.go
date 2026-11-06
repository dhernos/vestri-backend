package server

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"yourapp/internal/auth"
)

func TestMinecraftInstanceFailureLogging(t *testing.T) {
	var output bytes.Buffer
	previousOutput := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previousOutput) })
	server := &auth.GameServer{ID: "instance-id", StackName: "instance-stack"}
	for _, stage := range []string{"start", "reload"} {
		for _, retry := range []bool{false, true} {
			output.Reset()
			err := &url.Error{Op: "Post", URL: "https://secret-user:secret-password@worker", Err: fmt.Errorf("secret-response: %w", context.DeadlineExceeded)}
			logMinecraftInstanceFailure(context.Background(), stage, "node-id", server, retry, err)
			for _, want := range []string{"post_commit_failure", "stage=" + stage, `node="node-id"`, `server="instance-id"`, `stack="instance-stack"`, fmt.Sprintf("retry=%t", retry), "error_class=deadline_exceeded", "error_type=*url.Error"} {
				if !strings.Contains(output.String(), want) {
					t.Errorf("log %q missing %q", output.String(), want)
				}
			}
			if strings.Contains(output.String(), "secret") {
				t.Errorf("log exposed error content: %q", output.String())
			}
		}
	}
}

func TestMinecraftWorkerSuccessfulResponses(t *testing.T) {
	for _, test := range []struct {
		name      string
		endpoint  string
		status    int
		body      string
		wantError bool
	}{
		{name: "fresh stack output", endpoint: "/stack/up", status: http.StatusOK, body: "Container mcgame-fresh Started\n"},
		{name: "retry stack output", endpoint: "/stack/up", status: http.StatusOK, body: "Container mcgame-fresh Running\n"},
		{name: "sync acknowledged", endpoint: "/stack/velocity/reload", status: http.StatusNoContent},
		{name: "sync failed", endpoint: "/stack/velocity/reload", status: http.StatusBadGateway, wantError: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				if request.Method != http.MethodPost || request.URL.Path != test.endpoint {
					t.Errorf("unexpected request: %s %s", request.Method, request.URL.Path)
				}
				response.WriteHeader(test.status)
				_, _ = response.Write([]byte(test.body))
			}))
			defer workerServer.Close()
			previousClient := workerHTTPClient
			workerHTTPClient = workerServer.Client()
			defer func() { workerHTTPClient = previousClient }()
			baseURL, err := url.Parse(workerServer.URL)
			if err != nil {
				t.Fatal(err)
			}
			backend := &Server{}
			var output bytes.Buffer
			previousOutput := log.Writer()
			log.SetOutput(&output)
			defer log.SetOutput(previousOutput)
			if test.endpoint == "/stack/up" {
				_, err = backend.workerStackAction(context.Background(), baseURL, "test-key", "up", "mcgame-fresh")
			} else {
				err = reloadMinecraftProxyWorker(context.Background(), pluginWorker{server: backend, baseURL: baseURL, apiKey: "test-key"}, "node-id", &auth.GameServer{ID: "proxy-id", StackName: "proxy"})
			}
			if (err != nil) != test.wantError {
				t.Fatalf("error = %v, wantError = %t", err, test.wantError)
			}
			if test.wantError && !strings.Contains(output.String(), "worker_status=502") {
				t.Errorf("missing worker status in log: %q", output.String())
			}
			if !test.wantError && output.Len() != 0 {
				t.Errorf("successful operation logged a failure: %q", output.String())
			}
		})
	}
}
