package server

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
)

//go:embed gameserver_templates/*.json
var gameServerTemplateFS embed.FS

type gameServerTemplate struct {
	ID              string                         `json:"id"`
	Name            string                         `json:"name"`
	Description     string                         `json:"description"`
	Game            string                         `json:"game"`
	TemplateVersion string                         `json:"templateVersion"`
	ComposeInline   string                         `json:"composeInline,omitempty"`
	ComposeURL      string                         `json:"composeUrl,omitempty"`
	ConfigFiles     []gameServerTemplateConfigFile `json:"configFiles"`
}

type gameServerTemplateConfigFile struct {
	ID             string `json:"id"`
	Title          string `json:"title"`
	Path           string `json:"path"`
	Format         string `json:"format"`
	DefaultContent string `json:"defaultContent,omitempty"`
}

type gameServerConfigFileResponse struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	Path   string `json:"path"`
	Format string `json:"format"`
}

type gameServerStoredMetadata struct {
	TemplateName string                         `json:"templateName"`
	Game         string                         `json:"game"`
	ConfigFiles  []gameServerTemplateConfigFile `json:"configFiles"`
}

var (
	gameTemplateOnce sync.Once
	gameTemplateErr  error
	gameTemplateList []gameServerTemplate
	gameTemplateByID map[string]gameServerTemplate
)

func gameServerTemplates() ([]gameServerTemplate, error) {
	gameTemplateOnce.Do(func() {
		gameTemplateByID = make(map[string]gameServerTemplate)

		entries, err := fs.ReadDir(gameServerTemplateFS, "gameserver_templates")
		if err != nil {
			gameTemplateErr = err
			return
		}

		loaded := make([]gameServerTemplate, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(strings.ToLower(entry.Name()), ".json") {
				continue
			}

			raw, err := gameServerTemplateFS.ReadFile("gameserver_templates/" + entry.Name())
			if err != nil {
				gameTemplateErr = err
				return
			}

			var tpl gameServerTemplate
			if err := json.Unmarshal(raw, &tpl); err != nil {
				gameTemplateErr = fmt.Errorf("invalid template %s: %w", entry.Name(), err)
				return
			}

			if err := normalizeGameServerTemplate(&tpl); err != nil {
				gameTemplateErr = fmt.Errorf("invalid template %s: %w", entry.Name(), err)
				return
			}
			if _, exists := gameTemplateByID[tpl.ID]; exists {
				gameTemplateErr = fmt.Errorf("duplicate game server template id: %s", tpl.ID)
				return
			}

			gameTemplateByID[tpl.ID] = tpl
			loaded = append(loaded, tpl)
		}

		sort.Slice(loaded, func(i, j int) bool {
			if loaded[i].Name == loaded[j].Name {
				return loaded[i].ID < loaded[j].ID
			}
			return loaded[i].Name < loaded[j].Name
		})

		gameTemplateList = loaded
	})

	if gameTemplateErr != nil {
		return nil, gameTemplateErr
	}

	out := make([]gameServerTemplate, len(gameTemplateList))
	copy(out, gameTemplateList)
	return out, nil
}

func gameServerTemplateByID(id string) (*gameServerTemplate, error) {
	_, err := gameServerTemplates()
	if err != nil {
		return nil, err
	}

	tpl, ok := gameTemplateByID[id]
	if !ok {
		return nil, nil
	}

	copyTpl := tpl
	return &copyTpl, nil
}

func normalizeGameServerTemplate(tpl *gameServerTemplate) error {
	tpl.ID = strings.TrimSpace(tpl.ID)
	tpl.Name = strings.TrimSpace(tpl.Name)
	tpl.Description = strings.TrimSpace(tpl.Description)
	tpl.Game = strings.TrimSpace(tpl.Game)
	tpl.TemplateVersion = strings.TrimSpace(tpl.TemplateVersion)
	tpl.ComposeInline = strings.TrimSpace(tpl.ComposeInline)
	tpl.ComposeURL = strings.TrimSpace(tpl.ComposeURL)

	if tpl.ID == "" {
		return fmt.Errorf("id is required")
	}
	if tpl.Name == "" {
		return fmt.Errorf("name is required")
	}
	if tpl.TemplateVersion == "" {
		tpl.TemplateVersion = "1"
	}
	if tpl.ComposeInline == "" && tpl.ComposeURL == "" {
		return fmt.Errorf("composeInline or composeUrl is required")
	}

	normalizedConfigFiles := make([]gameServerTemplateConfigFile, 0, len(tpl.ConfigFiles))
	for _, cfg := range tpl.ConfigFiles {
		cfg.ID = strings.TrimSpace(cfg.ID)
		cfg.Title = strings.TrimSpace(cfg.Title)
		cfg.Path = normalizeTemplatePath(cfg.Path)
		cfg.Format = strings.TrimSpace(cfg.Format)

		if cfg.Path == "" {
			return fmt.Errorf("config file path is required")
		}
		if !isSafeTemplateRelativePath(cfg.Path) {
			return fmt.Errorf("invalid config file path: %s", cfg.Path)
		}
		if cfg.ID == "" {
			cfg.ID = strings.ReplaceAll(cfg.Path, "/", "_")
		}
		if cfg.Title == "" {
			cfg.Title = cfg.Path
		}
		if cfg.Format == "" {
			cfg.Format = "text"
		}

		normalizedConfigFiles = append(normalizedConfigFiles, cfg)
	}

	tpl.ConfigFiles = normalizedConfigFiles
	return nil
}

func normalizeTemplatePath(value string) string {
	value = strings.ReplaceAll(strings.TrimSpace(value), "\\", "/")
	value = strings.TrimPrefix(value, "./")
	return path.Clean(value)
}

func isSafeTemplateRelativePath(value string) bool {
	if value == "" || value == "." {
		return false
	}
	if strings.HasPrefix(value, "/") {
		return false
	}
	if strings.HasPrefix(value, "../") {
		return false
	}
	if strings.Contains(value, ":") {
		return false
	}
	return true
}

func configFilesToResponse(values []gameServerTemplateConfigFile) []gameServerConfigFileResponse {
	result := make([]gameServerConfigFileResponse, 0, len(values))
	for _, cfg := range values {
		result = append(result, gameServerConfigFileResponse{
			ID:     cfg.ID,
			Title:  cfg.Title,
			Path:   cfg.Path,
			Format: cfg.Format,
		})
	}
	return result
}

func parseGameServerMetadata(raw json.RawMessage) gameServerStoredMetadata {
	metadata := gameServerStoredMetadata{}
	if len(raw) == 0 {
		return metadata
	}
	_ = json.Unmarshal(raw, &metadata)
	return metadata
}
