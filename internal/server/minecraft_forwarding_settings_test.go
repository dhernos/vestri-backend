package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestMinecraftForwardingSettingsIdentifiesFailedFileWithoutSecrets(t *testing.T) {
	for _, file := range []string{backendServerPropertiesRelative, backendPaperGlobalRelative, backendSpigotConfigRelative} {
		for _, operation := range []string{"read", "write"} {
			t.Run(operation+" "+file, func(t *testing.T) {
				worker := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
					filename := request.URL.Query().Get("path")
					currentOperation := "read"
					if request.Method == http.MethodPost {
						currentOperation = "write"
						var payload map[string]string
						if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
							t.Error(err)
						}
						filename = payload["path"]
					}
					if currentOperation == operation && filename == "instance/"+file {
						http.Error(response, "SECRET worker response", http.StatusForbidden)
						return
					}
					response.WriteHeader(http.StatusOK)
				}))
				defer worker.Close()
				baseURL, _ := url.Parse(worker.URL)
				backend := &Server{}
				err := backend.applyVelocityBackendProxySettings(context.Background(), baseURL, "key", "instance", "PAPER", "SECRET forwarding secret", false)
				var failure *minecraftForwardingSettingsError
				if !errors.As(err, &failure) || failure.operation != operation || failure.file != file {
					t.Fatalf("unexpected failure: %v", err)
				}
				if strings.Contains(err.Error(), "SECRET") {
					t.Fatal("forwarding error exposed sensitive content")
				}
				if errors.Unwrap(err) == nil {
					t.Fatal("underlying failure was lost")
				}
			})
		}
	}
}
