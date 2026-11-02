package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"testing"

	"yourapp/internal/auth"

	"github.com/go-chi/chi/v5"
)

func TestMinecraftRequestInstanceRequiresExactKeyAndTemplate(t *testing.T) {
	requestID := "de6865e0-dee2-4685-99b3-ae22f64d2526"
	key := &auth.MinecraftAPIKey{ID: "key", TemplateID: "template"}
	digest := sha256.Sum256([]byte(key.ID + ":" + requestID))
	instance := auth.MinecraftInstance{ServerID: "server", KeyID: key.ID, TemplateID: key.TemplateID, RequestID: hex.EncodeToString(digest[:])}
	if found := minecraftRequestInstance(key, []auth.MinecraftInstance{instance}, requestID); found == nil || found.ServerID != "server" {
		t.Fatal("could not resolve saved request")
	}
	for _, other := range []*auth.MinecraftAPIKey{nil, {}, {ID: "other", TemplateID: key.TemplateID}, {ID: key.ID, TemplateID: "other"}} {
		if minecraftRequestInstance(other, []auth.MinecraftInstance{instance}, requestID) != nil {
			t.Fatal("request lookup escaped exact-key ownership")
		}
	}
	if minecraftRequestInstance(key, []auth.MinecraftInstance{instance}, "df98e1d3-c4e8-4fd3-b63c-9b471545f766") != nil {
		t.Fatal("resolved unrelated request")
	}
}

func TestMinecraftRequestLookupRejectsUnauthenticatedAndInvalidRequests(t *testing.T) {
	backend := &Server{}
	response := httptest.NewRecorder()
	backend.handleFindMinecraftRequestInstance(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", response.Code)
	}
	router := chi.NewRouter()
	router.Get("/requests/{requestId}", backend.handleFindMinecraftRequestInstance)
	request := httptest.NewRequest(http.MethodGet, "/requests/not-a-uuid", nil)
	request = request.WithContext(context.WithValue(request.Context(), minecraftAPIContextKey{}, minecraftAPIPrincipal{
		Key: &auth.MinecraftAPIKey{ID: "key"}, Node: &auth.WorkerNode{ID: "node"},
	}))
	response = httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusBadRequest {
		t.Fatalf("invalid request status = %d", response.Code)
	}
}
