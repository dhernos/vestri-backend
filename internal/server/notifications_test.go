package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yourapp/internal/auth"
)

func TestNotificationHandlersRequireSession(t *testing.T) {
	api := &Server{}
	for _, handler := range []http.HandlerFunc{api.handleListNotifications, api.handleUnreadNotifications, api.handleReadNotifications, api.handleNotificationSettings} {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(http.MethodGet, "/", nil))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("got %d, want 401", response.Code)
		}
	}
}

func TestNotificationSettingsRejectInvalidPayloads(t *testing.T) {
	api := &Server{}
	for _, body := range []string{
		`{"locale":"invalid"}`,
		`{"locale":"en","unexpected":true}`,
		`{"locale":"en","events":{"unknown_event":true}}`,
		`{"locale":"en"} {"locale":"de"}`,
		`{"locale":"en","webhookEnabled":true,"webhookUrl":"http://localhost"}`,
		`{"locale":"en","webhookEnabled":true,"webhookUrl":""}`,
	} {
		t.Run(body, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/api/notifications/settings", strings.NewReader(body))
			request = request.WithContext(context.WithValue(request.Context(), sessionContextKey, &auth.Session{UserID: "user"}))
			response := httptest.NewRecorder()
			api.handleNotificationSettings(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("got %d, want 400: %s", response.Code, response.Body.String())
			}
		})
	}
}

type notificationRoundTripper func(*http.Request) (*http.Response, error)

func (roundTrip notificationRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}

func TestNotificationWebhookPayloadAndStatus(t *testing.T) {
	previous := notificationWebhookClient
	t.Cleanup(func() { notificationWebhookClient = previous })
	for _, status := range []int{200, 204, 302, 429, 500} {
		notificationWebhookClient = &http.Client{Transport: notificationRoundTripper(func(request *http.Request) (*http.Response, error) {
			if request.Header.Get("X-Vestri-Notification-ID") != "notification" || request.Header.Get("X-Vestri-Event") != "server_down" {
				t.Error("missing event identity headers")
			}
			var payload map[string]any
			if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["content"] != "Server down" || payload["id"] != "notification" {
				t.Fatalf("unexpected payload: %v", payload)
			}
			mentions := payload["allowed_mentions"].(map[string]any)["parse"].([]any)
			if len(mentions) != 0 {
				t.Fatal("webhook mentions must be disabled")
			}
			return &http.Response{StatusCode: status, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}}, nil
		})}
		err := sendNotificationWebhook(context.Background(), "https://example.com/hook", notificationMessage{ID: "notification", Kind: "server_down"}, "Server down")
		if (err == nil) != (status >= 200 && status < 300) {
			t.Fatalf("status %d returned error %v", status, err)
		}
	}
}
