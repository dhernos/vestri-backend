package server

import (
	"net/http"
	"testing"
)

func TestParseWorkerImageStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		body    string
		want    bool
		wantErr bool
	}{
		{
			name: "bool payload true",
			body: `true`,
			want: true,
		},
		{
			name: "bool payload false",
			body: `false`,
			want: false,
		},
		{
			name: "camel case top-level true",
			body: `{"updateAvailable":true}`,
			want: true,
		},
		{
			name: "snake case top-level true",
			body: `{"update_available":true}`,
			want: true,
		},
		{
			name: "services include camel case true",
			body: `{"services":[{"service":"a","updateAvailable":false},{"service":"b","updateAvailable":true}]}`,
			want: true,
		},
		{
			name: "services include snake case true",
			body: `{"services":[{"service":"a","update_available":true}]}`,
			want: true,
		},
		{
			name: "all false",
			body: `{"updateAvailable":false,"services":[{"service":"a","updateAvailable":false}]}`,
			want: false,
		},
		{
			name:    "invalid payload",
			body:    `{`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseWorkerImageStatus([]byte(tt.body))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseWorkerImageStatus returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseWorkerImageStatus=%v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseWorkerDirectoryReservation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode int
		body       string
		want       bool
		wantErr    bool
	}{
		{
			name:       "directory reserved",
			statusCode: http.StatusCreated,
			body:       "",
			want:       true,
		},
		{
			name:       "directory reserved with legacy status",
			statusCode: http.StatusOK,
			body:       "",
			want:       true,
		},
		{
			name:       "directory already exists",
			statusCode: http.StatusConflict,
			body:       "path already exists",
			want:       false,
		},
		{
			name:       "unexpected bad request",
			statusCode: http.StatusBadRequest,
			body:       "invalid path",
			wantErr:    true,
		},
		{
			name:       "unexpected internal error",
			statusCode: http.StatusInternalServerError,
			body:       "boom",
			wantErr:    true,
		},
		{
			name:       "unexpected status",
			statusCode: http.StatusForbidden,
			body:       "forbidden",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseWorkerDirectoryReservation(tt.statusCode, tt.body)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("parseWorkerDirectoryReservation returned error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseWorkerDirectoryReservation=%v, want %v", got, tt.want)
			}
		})
	}
}
