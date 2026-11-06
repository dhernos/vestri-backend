package server

import "testing"

func TestOrphanCandidate(t *testing.T) {
	known := map[string]bool{"lobby": true}
	cases := []struct {
		entry satisfactoryWorkerEntry
		want  bool
	}{
		{satisfactoryWorkerEntry{Name: "lobby", Type: "dir"}, false},
		{satisfactoryWorkerEntry{Name: ".vestri-minecraft", Type: "dir"}, false},
		{satisfactoryWorkerEntry{Name: "satisfactory-blueprints", Type: "dir"}, false},
		{satisfactoryWorkerEntry{Name: "notes.txt", Type: "file"}, false},
		{satisfactoryWorkerEntry{Name: "link", Type: "symlink"}, false},
		{satisfactoryWorkerEntry{Name: "leftover", Type: "dir"}, true},
	}
	for _, tc := range cases {
		if got := orphanCandidate(tc.entry, known); got != tc.want {
			t.Errorf("orphanCandidate(%+v) = %v, want %v", tc.entry, got, tc.want)
		}
	}
}

func TestOrphanDirKind(t *testing.T) {
	instance := "mcgame-0123456789abcdef0123456789abcdef"
	cases := []struct {
		name     string
		children int
		want     string
	}{
		{"leftover", 0, orphanKindEmpty},
		{instance, 0, orphanKindEmpty},
		{instance, 3, orphanKindInstance},
		{"my-server", 3, ""},
		{"mcgame-short", 3, ""},
		{"mcgame-0123456789ABCDEF0123456789ABCDEF", 3, ""},
	}
	for _, tc := range cases {
		if got := orphanDirKind(tc.name, tc.children); got != tc.want {
			t.Errorf("orphanDirKind(%q, %d) = %q, want %q", tc.name, tc.children, got, tc.want)
		}
	}
}
