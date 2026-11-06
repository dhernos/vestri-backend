package server

import (
	"context"
	"net/url"
	"path"
)

func (s *Server) velocityPluginDataDirectory(ctx context.Context, baseURL *url.URL, apiKey, rootPath string) (string, error) {
	legacyDirectory := path.Join(rootPath, "data")
	pluginDirectory := path.Join(legacyDirectory, "plugins/vestri-dynamic")
	entries, err := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, pluginDirectory)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		if entry.Type == "file" && (entry.Name == "vestri-dynamic-config.json" || entry.Name == "vestri-players.json") {
			return pluginDirectory, nil
		}
	}
	entries, err = s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, legacyDirectory)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		switch entry.Name {
		case "vestri-dynamic-config.json", "vestri-dynamic-servers.json", "vestri-player-servers.json", "vestri-players.json", "vestri-player-policy.json", "vestri-player-logs":
			return legacyDirectory, nil
		}
	}
	return pluginDirectory, nil
}
