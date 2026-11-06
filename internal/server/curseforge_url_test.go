package server

import "testing"

func TestNormalizeCurseForgeModpackURL(t *testing.T) {
	testCases := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{
			name:  "modpack page",
			input: "https://www.curseforge.com/minecraft/modpacks/example-pack",
			want:  "https://www.curseforge.com/minecraft/modpacks/example-pack",
		},
		{
			name:  "modpack file page",
			input: "http://curseforge.com/minecraft/modpacks/example-pack/files/123456",
			want:  "https://www.curseforge.com/minecraft/modpacks/example-pack/files/123456",
		},
		{
			name:  "modpack URL with tracking query and fragment",
			input: "https://WWW.CURSEFORGE.COM/minecraft/modpacks/example-pack?tab=files#details",
			want:  "https://www.curseforge.com/minecraft/modpacks/example-pack",
		},
		{
			name:    "other host",
			input:   "https://www.curseforge.com.attacker.example/minecraft/modpacks/example-pack",
			wantErr: true,
		},
		{
			name:    "other Minecraft project type",
			input:   "https://www.curseforge.com/minecraft/mc-mods/example-mod",
			wantErr: true,
		},
		{
			name:    "invalid file ID",
			input:   "https://www.curseforge.com/minecraft/modpacks/example-pack/files/latest",
			wantErr: true,
		},
		{
			name:    "credentials",
			input:   "https://user@www.curseforge.com/minecraft/modpacks/example-pack",
			wantErr: true,
		},
		{
			name:    "non-HTTP scheme",
			input:   "javascript://www.curseforge.com/minecraft/modpacks/example-pack",
			wantErr: true,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := normalizeCurseForgeModpackURL(testCase.input)
			if (err != nil) != testCase.wantErr {
				t.Fatalf("normalizeCurseForgeModpackURL() error = %v, wantErr %v", err, testCase.wantErr)
			}
			if err == nil && got != testCase.want {
				t.Fatalf("normalizeCurseForgeModpackURL() = %q, want %q", got, testCase.want)
			}
		})
	}
}
