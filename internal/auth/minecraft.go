package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

type MinecraftResource struct {
	ID        string          `json:"id"`
	NodeID    string          `json:"nodeId"`
	Kind      string          `json:"kind"`
	Name      string          `json:"name"`
	Spec      json.RawMessage `json:"spec"`
	CreatedAt time.Time       `json:"createdAt"`
}

type MinecraftAPIKey struct {
	ID         string     `json:"id"`
	NodeID     string     `json:"nodeId"`
	TemplateID string     `json:"templateId"`
	UserID     string     `json:"-"`
	Name       string     `json:"name"`
	ExpiresAt  time.Time  `json:"expiresAt"`
	RevokedAt  *time.Time `json:"revokedAt"`
	CreatedAt  time.Time  `json:"createdAt"`
}

type MinecraftInstance struct {
	ServerID   string    `json:"serverId"`
	TemplateID string    `json:"templateId"`
	KeyID      string    `json:"keyId"`
	RequestID  string    `json:"requestId"`
	CreatedAt  time.Time `json:"createdAt"`
}

func (r *UserRepository) ListMinecraftResources(ctx context.Context, nodeID string) ([]MinecraftResource, error) {
	rows, err := r.DB.Query(ctx, `SELECT "id","nodeId","kind","name","spec","createdAt" FROM "MinecraftResource" WHERE "nodeId"=$1 ORDER BY "name"`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	resources := []MinecraftResource{}
	for rows.Next() {
		var resource MinecraftResource
		if err := rows.Scan(&resource.ID, &resource.NodeID, &resource.Kind, &resource.Name, &resource.Spec, &resource.CreatedAt); err != nil {
			return nil, err
		}
		resources = append(resources, resource)
	}
	return resources, rows.Err()
}

func (r *UserRepository) FindMinecraftResource(ctx context.Context, nodeID, id string) (*MinecraftResource, error) {
	var resource MinecraftResource
	err := r.DB.QueryRow(ctx, `SELECT "id","nodeId","kind","name","spec","createdAt" FROM "MinecraftResource" WHERE "nodeId"=$1 AND "id"=$2`, nodeID, id).Scan(&resource.ID, &resource.NodeID, &resource.Kind, &resource.Name, &resource.Spec, &resource.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &resource, err
}

func (r *UserRepository) CreateMinecraftResource(ctx context.Context, resource MinecraftResource) error {
	_, err := r.DB.Exec(ctx, `INSERT INTO "MinecraftResource" ("id","nodeId","kind","name","spec") VALUES ($1,$2,$3,$4,$5)`, resource.ID, resource.NodeID, resource.Kind, resource.Name, resource.Spec)
	return err
}

func (r *UserRepository) DeleteMinecraftResource(ctx context.Context, nodeID, id string) error {
	_, err := r.DB.Exec(ctx, `DELETE FROM "MinecraftResource" WHERE "nodeId"=$1 AND "id"=$2`, nodeID, id)
	return err
}

func (r *UserRepository) CreateMinecraftAPIKey(ctx context.Context, key MinecraftAPIKey, digest string) error {
	_, err := r.DB.Exec(ctx, `INSERT INTO "MinecraftAPIKey" ("id","nodeId","templateId","userId","name","digest","expiresAt") VALUES ($1,$2,$3,$4,$5,$6,$7)`, key.ID, key.NodeID, key.TemplateID, key.UserID, key.Name, digest, key.ExpiresAt)
	return err
}

func (r *UserRepository) FindMinecraftAPIKey(ctx context.Context, digest string) (*MinecraftAPIKey, error) {
	var key MinecraftAPIKey
	err := r.DB.QueryRow(ctx, `SELECT "id","nodeId","templateId","userId","name","expiresAt","revokedAt","createdAt" FROM "MinecraftAPIKey" WHERE "digest"=$1 AND "revokedAt" IS NULL AND "expiresAt">NOW()`, digest).Scan(&key.ID, &key.NodeID, &key.TemplateID, &key.UserID, &key.Name, &key.ExpiresAt, &key.RevokedAt, &key.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return &key, err
}

func (r *UserRepository) ListMinecraftAPIKeys(ctx context.Context, nodeID string) ([]MinecraftAPIKey, error) {
	rows, err := r.DB.Query(ctx, `SELECT "id","nodeId","templateId","userId","name","expiresAt","revokedAt","createdAt" FROM "MinecraftAPIKey" WHERE "nodeId"=$1 ORDER BY "createdAt" DESC`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	keys := []MinecraftAPIKey{}
	for rows.Next() {
		var key MinecraftAPIKey
		if err := rows.Scan(&key.ID, &key.NodeID, &key.TemplateID, &key.UserID, &key.Name, &key.ExpiresAt, &key.RevokedAt, &key.CreatedAt); err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, rows.Err()
}

func (r *UserRepository) RevokeMinecraftAPIKey(ctx context.Context, nodeID, id string) error {
	_, err := r.DB.Exec(ctx, `UPDATE "MinecraftAPIKey" SET "revokedAt"=NOW() WHERE "nodeId"=$1 AND "id"=$2`, nodeID, id)
	return err
}

func (r *UserRepository) ListMinecraftInstances(ctx context.Context, nodeID string) ([]MinecraftInstance, error) {
	rows, err := r.DB.Query(ctx, `SELECT "serverId","templateId",COALESCE("keyId",''),"requestId","createdAt" FROM "MinecraftInstance" WHERE "nodeId"=$1 ORDER BY "createdAt" DESC`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	instances := []MinecraftInstance{}
	for rows.Next() {
		var instance MinecraftInstance
		if err := rows.Scan(&instance.ServerID, &instance.TemplateID, &instance.KeyID, &instance.RequestID, &instance.CreatedAt); err != nil {
			return nil, err
		}
		instances = append(instances, instance)
	}
	return instances, rows.Err()
}

func (r *UserRepository) CreateMinecraftGameInstance(ctx context.Context, params CreateGameServerParams, instance MinecraftInstance) (*GameServer, error) {
	transaction, err := r.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer transaction.Rollback(ctx)
	server, err := createGameServer(ctx, transaction, params)
	if err != nil {
		return nil, err
	}
	_, err = transaction.Exec(ctx, `INSERT INTO "MinecraftInstance" ("serverId","nodeId","templateId","keyId","requestId") VALUES ($1,$2,$3,NULLIF($4,''),$5)`, server.ID, params.NodeID, instance.TemplateID, instance.KeyID, instance.RequestID)
	if err != nil {
		return nil, err
	}
	if err = transaction.Commit(ctx); err != nil {
		return nil, err
	}
	return server, nil
}
