package server

import "yourapp/internal/auth"

func canManageNodeInvites(nodeRole string) bool {
	return nodeRole == auth.NodeAccessOwner
}

func canUseNodeWorkerProxy(role string) bool {
	return role == auth.NodeAccessOwner
}

func canCreateGameServer(nodeRole string) bool {
	switch nodeRole {
	case auth.NodeAccessOwner, auth.NodeAccessAdmin:
		return true
	default:
		return false
	}
}

func canViewGameServer(serverRole string) bool {
	switch serverRole {
	case auth.NodeAccessOwner, auth.NodeAccessAdmin, auth.NodeAccessOperator, auth.NodeAccessViewer:
		return true
	default:
		return false
	}
}

func canManageGameServer(serverRole string) bool {
	switch serverRole {
	case auth.NodeAccessOwner, auth.NodeAccessAdmin:
		return true
	default:
		return false
	}
}

func canControlGameServer(serverRole string) bool {
	switch serverRole {
	case auth.NodeAccessOwner, auth.NodeAccessAdmin, auth.NodeAccessOperator:
		return true
	default:
		return false
	}
}

func canManageGameServerFiles(serverRole string) bool {
	switch serverRole {
	case auth.NodeAccessOwner, auth.NodeAccessAdmin:
		return true
	default:
		return false
	}
}

func canReadGameServerConsole(serverRole string) bool {
	switch serverRole {
	case auth.NodeAccessOwner, auth.NodeAccessAdmin, auth.NodeAccessOperator, auth.NodeAccessViewer:
		return true
	default:
		return false
	}
}

func canManageGameServerInvites(serverRole string) bool {
	return canManageGameServer(serverRole)
}
