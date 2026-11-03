package server

import (
	"context"
	"errors"
	"log"
	"net/url"
	"path"
	"regexp"
	"strings"
	"time"

	"yourapp/internal/auth"
)

const (
	orphanCleanupLock     = 7029012
	orphanCleanupInterval = 10 * time.Minute
	orphanKindEmpty       = "empty"
	orphanKindInstance    = "instance"
)

var dynamicInstanceDirPattern = regexp.MustCompile(`^mcgame-[a-f0-9]{32}$`)

// Shared top-level worker directories that never belong to a single game server.
var reservedWorkerDirs = map[string]bool{"satisfactory-blueprints": true}

// RunOrphanCleanup removes worker directories without a GameServer record. A directory is only
// deleted after it was classified identically in two consecutive runs, so in-flight creations survive.
func (s *Server) RunOrphanCleanup(ctx context.Context) {
	suspects := map[string]string{}
	ticker := time.NewTicker(orphanCleanupInterval)
	defer ticker.Stop()
	for {
		err := s.advisoryJob(ctx, orphanCleanupLock, orphanCleanupInterval-time.Minute, func(ctx context.Context) error {
			var err error
			suspects, err = s.cleanupWorkerOrphans(ctx, suspects)
			return err
		})
		if err != nil && ctx.Err() == nil {
			log.Printf("worker orphan cleanup failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) cleanupWorkerOrphans(ctx context.Context, previous map[string]string) (map[string]string, error) {
	rows, err := s.Users.DB.Query(ctx, `SELECT "id", "name", "baseUrl", "apiKey" FROM "WorkerNode"`)
	if err != nil {
		return previous, err
	}
	nodes := make([]auth.WorkerNode, 0)
	for rows.Next() {
		var node auth.WorkerNode
		if err := rows.Scan(&node.ID, &node.Name, &node.BaseURL, &node.APIKey); err != nil {
			rows.Close()
			return previous, err
		}
		nodes = append(nodes, node)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return previous, err
	}
	next := map[string]string{}
	var failures []error
	for i := range nodes {
		if err := s.cleanupNodeOrphans(ctx, &nodes[i], previous, next); err != nil {
			if ctx.Err() != nil {
				return next, ctx.Err()
			}
			log.Printf("worker orphan cleanup skipped node %s: %v", nodes[i].ID, err)
			failures = append(failures, err)
		}
	}
	if len(failures) == len(nodes) && len(failures) > 0 {
		return next, errors.Join(failures...)
	}
	return next, nil
}

func (s *Server) cleanupNodeOrphans(ctx context.Context, node *auth.WorkerNode, previous, next map[string]string) error {
	// Instance spawns hold this lock until their GameServer row is committed.
	unlock, err := s.lockNodePlugins(ctx, node.ID)
	if err != nil {
		return err
	}
	defer unlock()
	baseURL, apiKey, err := s.workerTargetFromNode(node)
	if err != nil {
		return err
	}
	entries, err := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, ".")
	if err != nil {
		return err
	}
	// Loaded after listing, across all nodes, because several nodes may share one worker root.
	known, err := s.gameServerRootDirs(ctx)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name
		if !orphanCandidate(entry, known) {
			continue
		}
		children, err := s.listSatisfactoryWorkerEntries(ctx, baseURL, apiKey, name)
		if err != nil {
			log.Printf("worker orphan cleanup could not inspect node=%s dir=%q: %v", node.ID, name, err)
			continue
		}
		kind := orphanDirKind(name, len(children))
		if kind == "" {
			continue
		}
		key := node.ID + "/" + name
		if previous[key] != kind {
			next[key] = kind
			continue
		}
		if kind == orphanKindInstance {
			if err := s.unregisterOrphanInstance(ctx, baseURL, apiKey, node.ID, name); err != nil {
				log.Printf("worker orphan cleanup could not unregister node=%s dir=%q from Velocity: %v", node.ID, name, err)
				next[key] = kind
				continue
			}
		}
		if err := s.workerDeletePath(ctx, baseURL, apiKey, name, kind == orphanKindInstance); err != nil {
			log.Printf("worker orphan cleanup could not delete node=%s dir=%q: %v", node.ID, name, err)
			next[key] = kind
			continue
		}
		log.Printf("worker orphan cleanup deleted %s directory node=%s dir=%q", kind, node.ID, name)
	}
	return nil
}

func orphanCandidate(entry satisfactoryWorkerEntry, known map[string]bool) bool {
	name := entry.Name
	return entry.Type == "dir" && name != "" && !strings.ContainsAny(name, `/\`) && !strings.HasPrefix(name, ".") &&
		!reservedWorkerDirs[name] && !known[name]
}

// Only empty directories or Vestri-generated instance directories are ever removed.
func orphanDirKind(name string, children int) string {
	if children == 0 {
		return orphanKindEmpty
	}
	if dynamicInstanceDirPattern.MatchString(name) {
		return orphanKindInstance
	}
	return ""
}

func (s *Server) gameServerRootDirs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.Users.DB.Query(ctx, `SELECT "rootPath" FROM "GameServer"`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	known := map[string]bool{}
	for rows.Next() {
		var rootPath string
		if err := rows.Scan(&rootPath); err != nil {
			return nil, err
		}
		clean := strings.TrimPrefix(path.Clean("/"+strings.TrimSpace(rootPath)), "/")
		known[strings.SplitN(clean, "/", 2)[0]] = true
	}
	return known, rows.Err()
}

func (s *Server) unregisterOrphanInstance(ctx context.Context, baseURL *url.URL, apiKey, nodeID, slug string) error {
	servers, err := s.Users.ListGameServersForNode(ctx, nodeID)
	if err != nil {
		return err
	}
	host := velocityBackendHostForSlug(slug)
	for i := range servers {
		proxy := &servers[i]
		if !isVelocityServer(proxy) {
			continue
		}
		content, missing, err := s.workerReadFileOptional(ctx, baseURL, apiKey, path.Join(proxy.RootPath, velocityTomlRelativePath))
		if err != nil {
			return err
		}
		if missing {
			continue
		}
		for name, address := range parseVelocityTomlServerEntries(content) {
			if !strings.EqualFold(strings.TrimSpace(strings.SplitN(address, ":", 2)[0]), host) {
				continue
			}
			if err := s.unregisterVelocityBackendFromProxy(ctx, baseURL, apiKey, proxy, name); err != nil {
				return err
			}
		}
	}
	return nil
}
