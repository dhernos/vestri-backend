package server

import (
	"strings"

	"yourapp/internal/auth"
)

func canManageNodeInvites(role string) bool {
	switch role {
	case auth.NodeAccessOwner:
		return true
	default:
		return false
	}
}

func canUseWorkerPath(role, method, workerPath string) bool {
	if role == auth.NodeAccessOwner || role == auth.NodeAccessAdmin {
		return true
	}

	cleanMethod := strings.ToUpper(strings.TrimSpace(method))
	cleanPath := normalizeWorkerPath(workerPath)

	switch role {
	case auth.NodeAccessOperator:
		return canOperatorUsePath(cleanMethod, cleanPath)
	case auth.NodeAccessViewer:
		return canViewerUsePath(cleanMethod, cleanPath)
	default:
		return false
	}
}

func canOperatorUsePath(method, path string) bool {
	if canViewerUsePath(method, path) {
		return true
	}
	if method != "POST" {
		return false
	}
	switch path {
	case "/stack/up", "/stack/down", "/stack/restart":
		return true
	default:
		return false
	}
}

func canViewerUsePath(method, path string) bool {
	if method != "GET" {
		return false
	}
	switch path {
	case "/health", "/stack/status":
		return true
	default:
		return false
	}
}

func normalizeWorkerPath(path string) string {
	normalized := "/" + strings.TrimPrefix(strings.TrimSpace(path), "/")
	if normalized != "/" {
		normalized = strings.TrimRight(normalized, "/")
	}
	return normalized
}

func canViewGameServers(role string) bool {
	switch role {
	case auth.NodeAccessOwner, auth.NodeAccessAdmin, auth.NodeAccessOperator, auth.NodeAccessViewer:
		return true
	default:
		return false
	}
}

func canCreateGameServer(role string) bool {
	switch role {
	case auth.NodeAccessOwner, auth.NodeAccessAdmin:
		return true
	default:
		return false
	}
}

func canControlGameServer(role string) bool {
	switch role {
	case auth.NodeAccessOwner, auth.NodeAccessAdmin, auth.NodeAccessOperator:
		return true
	default:
		return false
	}
}

func canManageGameServerFiles(role string) bool {
	switch role {
	case auth.NodeAccessOwner, auth.NodeAccessAdmin:
		return true
	default:
		return false
	}
}

func canReadGameServerConsole(role string) bool {
	switch role {
	case auth.NodeAccessOwner, auth.NodeAccessAdmin, auth.NodeAccessOperator:
		return true
	default:
		return false
	}
}
