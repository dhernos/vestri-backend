package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"yourapp/internal/auth"
)

func TestSupportsGameServerDatabases(t *testing.T) {
	templates, err := gameServerTemplates()
	if err != nil {
		t.Fatal(err)
	}
	var velocityTemplateID string
	for _, template := range templates {
		if isVelocityTemplate(&template) {
			velocityTemplateID = template.ID
			break
		}
	}
	if velocityTemplateID == "" {
		t.Fatal("no registered Velocity template")
	}

	tests := []struct {
		name   string
		server auth.GameServer
		want   bool
	}{
		{name: "Minecraft metadata", server: auth.GameServer{Metadata: json.RawMessage(`{"game":"minecraft"}`)}, want: true},
		{name: "Minecraft metadata ignores case and whitespace", server: auth.GameServer{Metadata: json.RawMessage(`{"game":"  MiNeCrAfT  "}`)}, want: true},
		{name: "Velocity template without metadata", server: auth.GameServer{TemplateID: velocityTemplateID}, want: true},
		{name: "Satisfactory rejected", server: auth.GameServer{Metadata: json.RawMessage(`{"game":"satisfactory"}`)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := supportsGameServerDatabases(&test.server); got != test.want {
				t.Errorf("supportsGameServerDatabases() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestEnsureNoGameServerDatabases(t *testing.T) {
	gameServer := &auth.GameServer{
		ID:              "server-id &owner=other-server",
		StackName:       "server-stack &stack=other-stack",
		CreatedByUserID: "user-controlled-owner",
	}
	tests := []struct {
		name      string
		status    int
		body      string
		wantError string
	}{
		{name: "empty databases allow deletion", status: http.StatusOK, body: `{"databases":[]}`},
		{
			name: "existing database blocks deletion", status: http.StatusOK,
			body:      `{"databases":[{"id":"database-id"}]}`,
			wantError: "delete this server's database containers in the Databases tab first",
		},
		{
			name: "invalid JSON blocks deletion", status: http.StatusOK,
			body:      `{"databases":`,
			wantError: "invalid database status response",
		},
		{
			name: "worker failure blocks deletion", status: http.StatusInternalServerError,
			body:      `{"databases":[]}`,
			wantError: "could not check database containers; check the worker and database storage before deleting this server",
		},
		{name: "older worker without endpoint allows deletion", status: http.StatusNotFound, body: "404 page not found"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := make(chan *http.Request, 1)
			workerServer := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
				requests <- request
				response.Header().Set("Content-Type", "application/json")
				response.WriteHeader(test.status)
				_, _ = response.Write([]byte(test.body))
			}))
			t.Cleanup(workerServer.Close)
			previousClient := workerHTTPClient
			workerHTTPClient = workerServer.Client()
			t.Cleanup(func() { workerHTTPClient = previousClient })
			baseURL, err := url.Parse(workerServer.URL + "?owner=user-controlled-owner&stack=user-controlled-stack")
			if err != nil {
				t.Fatal(err)
			}

			err = (&Server{}).ensureNoGameServerDatabases(context.Background(), baseURL, "test-worker-key", gameServer)
			if test.wantError == "" {
				if err != nil {
					t.Errorf("ensureNoGameServerDatabases() error = %v, want nil", err)
				}
			} else if err == nil || err.Error() != test.wantError {
				t.Errorf("ensureNoGameServerDatabases() error = %v, want %q", err, test.wantError)
			}

			select {
			case request := <-requests:
				if request.Method != http.MethodGet || request.URL.Path != "/databases" {
					t.Errorf("worker request = %s %s, want GET /databases", request.Method, request.URL.Path)
				}
				wantQuery := url.Values{"owner": {gameServer.ID}, "stack": {gameServer.StackName}}
				if got := request.URL.Query(); !reflect.DeepEqual(got, wantQuery) {
					t.Errorf("worker query = %v, want %v", got, wantQuery)
				}
				if got := request.Header.Get("X-API-Key"); got != "test-worker-key" {
					t.Errorf("worker API key = %q, want test-worker-key", got)
				}
			default:
				t.Error("worker received no database status request")
			}
		})
	}
}

func TestCanManageGameServerDatabasesRoles(t *testing.T) {
	tests := []struct {
		role string
		want bool
	}{
		{role: auth.NodeAccessOwner, want: true},
		{role: auth.NodeAccessAdmin, want: true},
		{role: auth.NodeAccessOperator},
		{role: auth.NodeAccessViewer},
		{role: "file-manager"},
		{role: "unknown"},
		{role: ""},
	}
	for _, test := range tests {
		t.Run(test.role, func(t *testing.T) {
			if got := canManageGameServer(test.role); got != test.want {
				t.Errorf("canManageGameServer(%q) = %v, want %v", test.role, got, test.want)
			}
		})
	}
}
