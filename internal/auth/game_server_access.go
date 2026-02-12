package auth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type GameServerWithAccess struct {
	GameServer
	AccessRole string
}

type GameServerInvite struct {
	ID          string
	ServerID    string
	ServerName  string
	ServerSlug  string
	NodeID      string
	NodeName    string
	NodeSlug    string
	InviterUser string
	InviterMail string
	Email       string
	Permission  string
	Token       string
	ExpiresAt   time.Time
	AcceptedAt  *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type GameServerGuest struct {
	ServerID   string
	ServerName string
	ServerSlug string
	NodeID     string
	NodeName   string
	NodeSlug   string
	UserID     string
	Name       *string
	Email      string
	Permission string
	CreatedAt  time.Time
}

func (r *UserRepository) ListAccessibleGameServersForNode(ctx context.Context, userID string, node *WorkerNode) ([]GameServerWithAccess, error) {
	if node == nil {
		return nil, nil
	}

	if node.OwnerUserID == userID {
		servers, err := r.ListGameServersForNode(ctx, node.ID)
		if err != nil {
			return nil, err
		}
		result := make([]GameServerWithAccess, 0, len(servers))
		for i := range servers {
			result = append(result, GameServerWithAccess{
				GameServer: servers[i],
				AccessRole: NodeAccessOwner,
			})
		}
		return result, nil
	}

	rows, err := r.DB.Query(ctx, `
		SELECT
			s."id",
			s."nodeId",
			s."slug",
			s."name",
			s."templateId",
			s."templateVersion",
			s."stackName",
			s."rootPath",
			s."composePath",
			s."metadata",
			s."createdByUserId",
			s."createdAt",
			s."updatedAt",
			g."permission"
		FROM "GameServer" s
		INNER JOIN "GameServerGuest" g
			ON g."serverId"=s."id" AND g."userId"=$1
		WHERE s."nodeId"=$2
		ORDER BY s."createdAt" DESC
	`, userID, node.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make([]GameServerWithAccess, 0)
	for rows.Next() {
		server, err := scanGameServerWithAccess(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, *server)
	}
	return result, rows.Err()
}

func (r *UserRepository) FindAccessibleGameServerByRefForNode(ctx context.Context, userID string, node *WorkerNode, ref string) (*GameServerWithAccess, error) {
	if node == nil {
		return nil, nil
	}

	if node.OwnerUserID == userID {
		server, err := r.FindGameServerByRefForNode(ctx, node.ID, ref)
		if err != nil || server == nil {
			return nil, err
		}
		return &GameServerWithAccess{GameServer: *server, AccessRole: NodeAccessOwner}, nil
	}

	row := r.DB.QueryRow(ctx, `
		SELECT
			s."id",
			s."nodeId",
			s."slug",
			s."name",
			s."templateId",
			s."templateVersion",
			s."stackName",
			s."rootPath",
			s."composePath",
			s."metadata",
			s."createdByUserId",
			s."createdAt",
			s."updatedAt",
			g."permission"
		FROM "GameServer" s
		INNER JOIN "GameServerGuest" g
			ON g."serverId"=s."id" AND g."userId"=$1
		WHERE s."nodeId"=$2
		  AND (s."id"=$3 OR s."slug"=$3)
		LIMIT 1
	`, userID, node.ID, ref)

	server, err := scanGameServerWithAccess(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return server, err
}

func (r *UserRepository) CreateGameServerInvite(ctx context.Context, serverID, inviterUserID, email, permission string, expiresAt time.Time) (*GameServerInvite, error) {
	tx, err := r.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	token := strings.ReplaceAll(uuid.NewString(), "-", "")

	if _, err := tx.Exec(ctx, `
		DELETE FROM "GameServerInvite"
		WHERE "serverId"=$1
		  AND LOWER("email")=LOWER($2)
		  AND "acceptedAt" IS NULL
	`, serverID, normalizedEmail); err != nil {
		return nil, err
	}

	id := uuid.NewString()
	row := tx.QueryRow(ctx, `
		INSERT INTO "GameServerInvite"
		("id","serverId","inviterUserId","email","permission","token","expiresAt")
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING "id","serverId","inviterUserId","email","permission","token","expiresAt","acceptedAt","createdAt","updatedAt"
	`, id, serverID, inviterUserID, normalizedEmail, permission, token, expiresAt)

	invite, err := scanGameServerInvite(row)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return invite, nil
}

func (r *UserRepository) ListPendingGameServerInvitesForServer(ctx context.Context, serverID string) ([]GameServerInvite, error) {
	rows, err := r.DB.Query(ctx, `
		SELECT
			i."id",
			i."serverId",
			s."name",
			s."slug",
			n."id",
			n."name",
			n."slug",
			i."inviterUserId",
			u."email",
			i."email",
			i."permission",
			i."token",
			i."expiresAt",
			i."acceptedAt",
			i."createdAt",
			i."updatedAt"
		FROM "GameServerInvite" i
		INNER JOIN "GameServer" s ON s."id"=i."serverId"
		INNER JOIN "WorkerNode" n ON n."id"=s."nodeId"
		INNER JOIN "User" u ON u."id"=i."inviterUserId"
		WHERE i."serverId"=$1
		  AND i."acceptedAt" IS NULL
		  AND i."expiresAt" > NOW()
		ORDER BY i."createdAt" DESC
	`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	invites := make([]GameServerInvite, 0)
	for rows.Next() {
		invite, err := scanGameServerInviteWithNodeAndServer(rows)
		if err != nil {
			return nil, err
		}
		invites = append(invites, *invite)
	}
	return invites, rows.Err()
}

func (r *UserRepository) ListIncomingGameServerInvites(ctx context.Context, email string) ([]GameServerInvite, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	rows, err := r.DB.Query(ctx, `
		SELECT
			i."id",
			i."serverId",
			s."name",
			s."slug",
			n."id",
			n."name",
			n."slug",
			i."inviterUserId",
			u."email",
			i."email",
			i."permission",
			i."token",
			i."expiresAt",
			i."acceptedAt",
			i."createdAt",
			i."updatedAt"
		FROM "GameServerInvite" i
		INNER JOIN "GameServer" s ON s."id"=i."serverId"
		INNER JOIN "WorkerNode" n ON n."id"=s."nodeId"
		INNER JOIN "User" u ON u."id"=i."inviterUserId"
		WHERE LOWER(i."email")=LOWER($1)
		  AND i."acceptedAt" IS NULL
		  AND i."expiresAt" > NOW()
		ORDER BY i."createdAt" DESC
	`, normalizedEmail)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	invites := make([]GameServerInvite, 0)
	for rows.Next() {
		invite, err := scanGameServerInviteWithNodeAndServer(rows)
		if err != nil {
			return nil, err
		}
		invites = append(invites, *invite)
	}
	return invites, rows.Err()
}

func (r *UserRepository) RevokeGameServerInvite(ctx context.Context, serverID, inviteID string) (bool, error) {
	tag, err := r.DB.Exec(ctx, `
		DELETE FROM "GameServerInvite"
		WHERE "id"=$1
		  AND "serverId"=$2
		  AND "acceptedAt" IS NULL
	`, inviteID, serverID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *UserRepository) ListGameServerGuests(ctx context.Context, serverID string) ([]GameServerGuest, error) {
	rows, err := r.DB.Query(ctx, `
		SELECT
			g."serverId",
			s."name",
			s."slug",
			n."id",
			n."name",
			n."slug",
			u."id",
			u."name",
			u."email",
			g."permission",
			g."createdAt"
		FROM "GameServerGuest" g
		INNER JOIN "GameServer" s ON s."id"=g."serverId"
		INNER JOIN "WorkerNode" n ON n."id"=s."nodeId"
		INNER JOIN "User" u ON u."id"=g."userId"
		WHERE g."serverId"=$1
		ORDER BY g."createdAt" ASC
	`, serverID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	guests := make([]GameServerGuest, 0)
	for rows.Next() {
		guest, err := scanGameServerGuest(rows)
		if err != nil {
			return nil, err
		}
		guests = append(guests, *guest)
	}
	return guests, rows.Err()
}

func (r *UserRepository) RemoveGameServerGuest(ctx context.Context, serverID, userID string) (bool, error) {
	tag, err := r.DB.Exec(ctx, `
		DELETE FROM "GameServerGuest"
		WHERE "serverId"=$1
		  AND "userId"=$2
	`, serverID, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *UserRepository) UpsertGameServerGuest(ctx context.Context, serverID, userID, permission string) error {
	_, err := r.DB.Exec(ctx, `
		INSERT INTO "GameServerGuest" ("id","serverId","userId","permission")
		VALUES ($1,$2,$3,$4)
		ON CONFLICT ("serverId","userId")
		DO UPDATE SET "permission"=EXCLUDED."permission"
	`, uuid.NewString(), serverID, userID, permission)
	return err
}

func (r *UserRepository) AcceptGameServerInvite(ctx context.Context, inviteID, userID, email string) (*GameServerInvite, error) {
	tx, err := r.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	var (
		invite     GameServerInvite
		nodeID     string
		acceptedAt sql.NullTime
	)

	if err := tx.QueryRow(ctx, `
		SELECT
			i."id",
			i."serverId",
			s."name",
			s."slug",
			n."id",
			n."name",
			n."slug",
			i."inviterUserId",
			u."email",
			i."email",
			i."permission",
			i."token",
			i."expiresAt",
			i."acceptedAt",
			i."createdAt",
			i."updatedAt",
			s."nodeId"
		FROM "GameServerInvite" i
		INNER JOIN "GameServer" s ON s."id"=i."serverId"
		INNER JOIN "WorkerNode" n ON n."id"=s."nodeId"
		INNER JOIN "User" u ON u."id"=i."inviterUserId"
		WHERE i."id"=$1
		  AND LOWER(i."email")=LOWER($2)
		FOR UPDATE
	`, inviteID, normalizedEmail).Scan(
		&invite.ID,
		&invite.ServerID,
		&invite.ServerName,
		&invite.ServerSlug,
		&invite.NodeID,
		&invite.NodeName,
		&invite.NodeSlug,
		&invite.InviterUser,
		&invite.InviterMail,
		&invite.Email,
		&invite.Permission,
		&invite.Token,
		&invite.ExpiresAt,
		&acceptedAt,
		&invite.CreatedAt,
		&invite.UpdatedAt,
		&nodeID,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if acceptedAt.Valid || invite.ExpiresAt.Before(time.Now()) {
		return nil, nil
	}

	now := time.Now()
	if _, err := tx.Exec(ctx, `
		UPDATE "GameServerInvite"
		SET "acceptedAt"=$1
		WHERE "id"=$2
	`, now, inviteID); err != nil {
		return nil, err
	}
	invite.AcceptedAt = &now

	nodeGuestID := uuid.NewString()
	if _, err := tx.Exec(ctx, `
		INSERT INTO "WorkerNodeGuest" ("id","nodeId","userId","permission")
		VALUES ($1,$2,$3,$4)
		ON CONFLICT ("nodeId","userId")
		DO NOTHING
	`, nodeGuestID, nodeID, userID, NodeAccessViewer); err != nil {
		return nil, err
	}

	serverGuestID := uuid.NewString()
	if _, err := tx.Exec(ctx, `
		INSERT INTO "GameServerGuest" ("id","serverId","userId","permission")
		VALUES ($1,$2,$3,$4)
		ON CONFLICT ("serverId","userId")
		DO UPDATE SET "permission"=EXCLUDED."permission"
	`, serverGuestID, invite.ServerID, userID, invite.Permission); err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}

	return &invite, nil
}

func scanGameServerWithAccess(row pgx.Row) (*GameServerWithAccess, error) {
	var server GameServerWithAccess
	if err := row.Scan(
		&server.ID,
		&server.NodeID,
		&server.Slug,
		&server.Name,
		&server.TemplateID,
		&server.TemplateVersion,
		&server.StackName,
		&server.RootPath,
		&server.ComposePath,
		&server.Metadata,
		&server.CreatedByUserID,
		&server.CreatedAt,
		&server.UpdatedAt,
		&server.AccessRole,
	); err != nil {
		return nil, err
	}
	if len(server.Metadata) == 0 {
		server.Metadata = json.RawMessage("{}")
	}
	return &server, nil
}

func scanGameServerInvite(row pgx.Row) (*GameServerInvite, error) {
	var (
		invite     GameServerInvite
		acceptedAt sql.NullTime
	)
	if err := row.Scan(
		&invite.ID,
		&invite.ServerID,
		&invite.InviterUser,
		&invite.Email,
		&invite.Permission,
		&invite.Token,
		&invite.ExpiresAt,
		&acceptedAt,
		&invite.CreatedAt,
		&invite.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if acceptedAt.Valid {
		invite.AcceptedAt = &acceptedAt.Time
	}
	return &invite, nil
}

func scanGameServerInviteWithNodeAndServer(row pgx.Row) (*GameServerInvite, error) {
	var (
		invite     GameServerInvite
		acceptedAt sql.NullTime
	)
	if err := row.Scan(
		&invite.ID,
		&invite.ServerID,
		&invite.ServerName,
		&invite.ServerSlug,
		&invite.NodeID,
		&invite.NodeName,
		&invite.NodeSlug,
		&invite.InviterUser,
		&invite.InviterMail,
		&invite.Email,
		&invite.Permission,
		&invite.Token,
		&invite.ExpiresAt,
		&acceptedAt,
		&invite.CreatedAt,
		&invite.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if acceptedAt.Valid {
		invite.AcceptedAt = &acceptedAt.Time
	}
	return &invite, nil
}

func scanGameServerGuest(row pgx.Row) (*GameServerGuest, error) {
	var (
		guest GameServerGuest
		name  sql.NullString
	)
	if err := row.Scan(
		&guest.ServerID,
		&guest.ServerName,
		&guest.ServerSlug,
		&guest.NodeID,
		&guest.NodeName,
		&guest.NodeSlug,
		&guest.UserID,
		&name,
		&guest.Email,
		&guest.Permission,
		&guest.CreatedAt,
	); err != nil {
		return nil, err
	}
	if name.Valid {
		guest.Name = &name.String
	}
	return &guest, nil
}
