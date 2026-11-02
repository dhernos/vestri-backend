package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"yourapp/internal/auth"
)

func (s *Server) RunNotifications(ctx context.Context) {
	var workers sync.WaitGroup
	for _, job := range []struct {
		lock int64
		run  func(context.Context) error
	}{
		{7029010, s.monitorNotificationHealth}, {7029011, s.deliverNotifications},
	} {
		workers.Add(1)
		go func(lock int64, run func(context.Context) error) {
			defer workers.Done()
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			for {
				if ctx.Err() != nil {
					return
				}
				if err := s.notificationJob(ctx, lock, run); err != nil && ctx.Err() == nil {
					log.Printf("notification job %d failed: %v", lock, err)
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}(job.lock, job.run)
	}
	workers.Wait()
}

func (s *Server) notificationJob(ctx context.Context, lock int64, run func(context.Context) error) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	connection, err := s.Users.DB.Acquire(ctx)
	if err != nil {
		return err
	}
	defer connection.Release()
	var locked bool
	if err := connection.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, lock).Scan(&locked); err != nil {
		return err
	}
	if !locked {
		return nil
	}
	defer func() {
		unlockCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := connection.Exec(unlockCtx, `SELECT pg_advisory_unlock($1)`, lock); err != nil {
			_ = connection.Conn().Close(unlockCtx)
		}
	}()
	return run(ctx)
}

func (s *Server) monitorNotificationHealth(ctx context.Context) error {
	rows, err := s.Users.DB.Query(ctx, `SELECT "id", "name", "baseUrl", "apiKey" FROM "WorkerNode"`)
	if err != nil {
		return err
	}
	nodes := make([]auth.WorkerNode, 0)
	for rows.Next() {
		var node auth.WorkerNode
		if err := rows.Scan(&node.ID, &node.Name, &node.BaseURL, &node.APIKey); err != nil {
			rows.Close()
			return err
		}
		nodes = append(nodes, node)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	var workers sync.WaitGroup
	semaphore := make(chan struct{}, 4)
	for _, node := range nodes {
		select {
		case semaphore <- struct{}{}:
		case <-ctx.Done():
			workers.Wait()
			return ctx.Err()
		}
		workers.Add(1)
		go func(node auth.WorkerNode) {
			defer workers.Done()
			defer func() { <-semaphore }()
			if err := s.monitorNotificationNode(ctx, &node); err != nil && ctx.Err() == nil {
				log.Printf("notification health check failed for node %s: %v", node.ID, err)
			}
		}(node)
	}
	workers.Wait()
	return ctx.Err()
}

func (s *Server) monitorNotificationNode(ctx context.Context, node *auth.WorkerNode) error {
	baseURL, apiKey, targetErr := s.workerTargetFromNode(node)
	reachable, healthy := false, false
	if targetErr == nil {
		checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		code, body, err := s.callWorkerJSON(checkCtx, baseURL, apiKey, "GET", "/health", nil)
		cancel()
		var status struct {
			Status   string `json:"status"`
			External string `json:"external_service"`
		}
		reachable = err == nil && code >= 200 && code < 300
		healthy = reachable && json.Unmarshal(body, &status) == nil && status.Status == "OK" && status.External == "OK"
	}
	if err := s.recordNotificationHealth(ctx, node, nil, "worker_unhealthy", !healthy, healthy); err != nil {
		return err
	}
	servers, err := s.Users.ListGameServersForNode(ctx, node.ID)
	if err != nil {
		return err
	}
	for index := range servers {
		gameServer := &servers[index]
		if !reachable {
			if err := s.recordNotificationHealth(ctx, node, gameServer, "server_down", false, false); err != nil {
				return err
			}
			continue
		}
		checkCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		state, _, err := s.workerStackStatus(checkCtx, baseURL, apiKey, gameServer.StackName)
		cancel()
		if err := s.recordNotificationHealth(ctx, node, gameServer, "server_down", err == nil && state == "down", err == nil && state == "up"); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) recordNotificationHealth(ctx context.Context, node *auth.WorkerNode, gameServer *auth.GameServer, kind string, unhealthy, healthy bool) error {
	resourceID, serverID, serverName := node.ID, "", ""
	var serverReference any
	if gameServer != nil {
		resourceID, serverID, serverName = gameServer.ID, gameServer.ID, gameServer.Name
		serverReference = serverID
	}
	tx, err := s.Users.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	_, err = tx.Exec(ctx, `INSERT INTO "NotificationHealth" ("kind", "resourceId", "nodeId", "serverId") VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING`, kind, resourceID, node.ID, serverReference)
	if err != nil {
		return err
	}
	var since *time.Time
	var sent, wasHealthy bool
	if err := tx.QueryRow(ctx, `SELECT "since", "sent", "wasHealthy" FROM "NotificationHealth" WHERE "kind"=$1 AND "resourceId"=$2 FOR UPDATE`, kind, resourceID).Scan(&since, &sent, &wasHealthy); err != nil {
		return err
	}
	previous := notificationFailure{Sent: sent}
	if since != nil {
		previous.Since = *since
	}
	if kind == "server_down" && !wasHealthy {
		unhealthy = false
	}
	next, emit := advanceNotificationFailure(previous, unhealthy, time.Now())
	var nextSince *time.Time
	if !next.Since.IsZero() {
		nextSince = &next.Since
	}
	if _, err := tx.Exec(ctx, `UPDATE "NotificationHealth" SET "since"=$3, "sent"=$4, "wasHealthy"=$5 WHERE "kind"=$1 AND "resourceId"=$2`, kind, resourceID, nextSince, next.Sent, wasHealthy || healthy); err != nil {
		return err
	}
	if emit {
		if _, err := tx.Exec(ctx, `SELECT vestri_notify($1,$2,$3,$4,$5)`, kind, node.ID, node.Name, serverID, serverName); err != nil {
			return fmt.Errorf("persist health notification: %w", err)
		}
	}
	return tx.Commit(ctx)
}
