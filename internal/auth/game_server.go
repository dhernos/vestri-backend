package auth

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type GameServer struct {
	ID              string
	NodeID          string
	Slug            string
	Name            string
	TemplateID      string
	TemplateVersion string
	StackName       string
	RootPath        string
	ComposePath     string
	Metadata        json.RawMessage
	CreatedByUserID string
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type CreateGameServerParams struct {
	NodeID          string
	Slug            string
	Name            string
	TemplateID      string
	TemplateVersion string
	StackName       string
	RootPath        string
	ComposePath     string
	Metadata        json.RawMessage
	CreatedByUserID string
}

func (r *UserRepository) CreateGameServer(ctx context.Context, params CreateGameServerParams) (*GameServer, error) {
	id := uuid.NewString()

	templateVersion := params.TemplateVersion
	if templateVersion == "" {
		templateVersion = "1"
	}

	metadata := params.Metadata
	if len(metadata) == 0 {
		metadata = json.RawMessage("{}")
	}

	row := r.DB.QueryRow(ctx, `
		INSERT INTO "GameServer"
		("id","nodeId","slug","name","templateId","templateVersion","stackName","rootPath","composePath","metadata","createdByUserId")
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING "id","nodeId","slug","name","templateId","templateVersion","stackName","rootPath","composePath","metadata","createdByUserId","createdAt","updatedAt"
	`, id, params.NodeID, params.Slug, params.Name, params.TemplateID, templateVersion, params.StackName, params.RootPath, params.ComposePath, metadata, params.CreatedByUserID)

	return scanGameServer(row)
}

func (r *UserRepository) ListGameServersForNode(ctx context.Context, nodeID string) ([]GameServer, error) {
	rows, err := r.DB.Query(ctx, `
		SELECT "id","nodeId","slug","name","templateId","templateVersion","stackName","rootPath","composePath","metadata","createdByUserId","createdAt","updatedAt"
		FROM "GameServer"
		WHERE "nodeId"=$1
		ORDER BY "createdAt" DESC
	`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	servers := make([]GameServer, 0)
	for rows.Next() {
		srv, err := scanGameServer(rows)
		if err != nil {
			return nil, err
		}
		servers = append(servers, *srv)
	}

	return servers, rows.Err()
}

func (r *UserRepository) FindGameServerByRefForNode(ctx context.Context, nodeID, ref string) (*GameServer, error) {
	row := r.DB.QueryRow(ctx, `
		SELECT "id","nodeId","slug","name","templateId","templateVersion","stackName","rootPath","composePath","metadata","createdByUserId","createdAt","updatedAt"
		FROM "GameServer"
		WHERE "nodeId"=$1
		  AND ("id"=$2 OR "slug"=$2)
		LIMIT 1
	`, nodeID, ref)

	srv, err := scanGameServer(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return srv, err
}

func (r *UserRepository) GameServerSlugExists(ctx context.Context, nodeID, slug string) (bool, error) {
	row := r.DB.QueryRow(ctx, `
		SELECT 1
		FROM "GameServer"
		WHERE "nodeId"=$1
		  AND "slug"=$2
		LIMIT 1
	`, nodeID, slug)

	var dummy int
	if err := row.Scan(&dummy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *UserRepository) DeleteGameServerByID(ctx context.Context, nodeID, serverID string) (bool, error) {
	tag, err := r.DB.Exec(ctx, `
		DELETE FROM "GameServer"
		WHERE "id"=$1
		  AND "nodeId"=$2
	`, serverID, nodeID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func scanGameServer(row pgx.Row) (*GameServer, error) {
	var srv GameServer
	if err := row.Scan(
		&srv.ID,
		&srv.NodeID,
		&srv.Slug,
		&srv.Name,
		&srv.TemplateID,
		&srv.TemplateVersion,
		&srv.StackName,
		&srv.RootPath,
		&srv.ComposePath,
		&srv.Metadata,
		&srv.CreatedByUserID,
		&srv.CreatedAt,
		&srv.UpdatedAt,
	); err != nil {
		return nil, err
	}

	if len(srv.Metadata) == 0 {
		srv.Metadata = json.RawMessage("{}")
	}

	return &srv, nil
}
