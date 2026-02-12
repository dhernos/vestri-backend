package auth

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

const (
	NodeAccessOwner    = "owner"
	NodeAccessAdmin    = "admin"
	NodeAccessOperator = "operator"
	NodeAccessViewer   = "viewer"
)

type WorkerNode struct {
	ID          string
	Slug        string
	Name        string
	BaseURL     string
	APIKey      string
	OwnerUserID string
	AccessRole  string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type WorkerNodeInvite struct {
	ID          string
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

type WorkerNodeGuest struct {
	NodeID     string
	NodeName   string
	NodeSlug   string
	UserID     string
	Name       *string
	Email      string
	Permission string
	CreatedAt  time.Time
}

func (r *UserRepository) CreateWorkerNode(ctx context.Context, slug, name, baseURL, apiKey, ownerUserID string) (*WorkerNode, error) {
	id := uuid.NewString()
	row := r.DB.QueryRow(ctx, `
		INSERT INTO "WorkerNode" ("id","slug","name","baseUrl","apiKey","ownerUserId")
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING "id","slug","name","baseUrl","apiKey","ownerUserId","createdAt","updatedAt"
	`, id, slug, name, baseURL, apiKey, ownerUserID)
	node, err := scanWorkerNode(row)
	if err != nil {
		return nil, err
	}
	node.AccessRole = NodeAccessOwner
	return node, nil
}

func (r *UserRepository) UpdateWorkerNodeAPIKey(ctx context.Context, nodeID, apiKey string) error {
	_, err := r.DB.Exec(ctx, `
		UPDATE "WorkerNode"
		SET "apiKey"=$1
		WHERE "id"=$2
	`, apiKey, nodeID)
	return err
}

func (r *UserRepository) ListAccessibleWorkerNodes(ctx context.Context, userID string) ([]WorkerNode, error) {
	rows, err := r.DB.Query(ctx, `
		SELECT
			n."id",
			n."slug",
			n."name",
			n."baseUrl",
			n."apiKey",
			n."ownerUserId",
			CASE
				WHEN n."ownerUserId"=$1 THEN 'owner'
				ELSE COALESCE(g."permission", 'viewer')
			END AS "accessRole",
			n."createdAt",
			n."updatedAt"
		FROM "WorkerNode" n
		LEFT JOIN "WorkerNodeGuest" g
			ON g."nodeId"=n."id" AND g."userId"=$1
		WHERE n."ownerUserId"=$1 OR g."userId"=$1
		ORDER BY n."createdAt" DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var nodes []WorkerNode
	for rows.Next() {
		node, err := scanWorkerNodeWithAccess(rows)
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, *node)
	}
	return nodes, rows.Err()
}

func (r *UserRepository) FindAccessibleWorkerNodeByRef(ctx context.Context, userID, ref string) (*WorkerNode, error) {
	row := r.DB.QueryRow(ctx, `
		SELECT
			n."id",
			n."slug",
			n."name",
			n."baseUrl",
			n."apiKey",
			n."ownerUserId",
			CASE
				WHEN n."ownerUserId"=$1 THEN 'owner'
				ELSE COALESCE(g."permission", 'viewer')
			END AS "accessRole",
			n."createdAt",
			n."updatedAt"
		FROM "WorkerNode" n
		LEFT JOIN "WorkerNodeGuest" g
			ON g."nodeId"=n."id" AND g."userId"=$1
		WHERE
			(n."id"=$2 OR n."slug"=$2)
			AND (n."ownerUserId"=$1 OR g."userId"=$1)
		LIMIT 1
	`, userID, ref)

	node, err := scanWorkerNodeWithAccess(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return node, err
}

func (r *UserRepository) FindWorkerNodeForOwnerByRef(ctx context.Context, ownerUserID, ref string) (*WorkerNode, error) {
	row := r.DB.QueryRow(ctx, `
		SELECT "id","slug","name","baseUrl","apiKey","ownerUserId","createdAt","updatedAt"
		FROM "WorkerNode"
		WHERE "ownerUserId"=$1
		  AND ("id"=$2 OR "slug"=$2)
		LIMIT 1
	`, ownerUserID, ref)

	node, err := scanWorkerNode(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if node != nil {
		node.AccessRole = NodeAccessOwner
	}
	return node, err
}

func (r *UserRepository) WorkerNodeSlugExists(ctx context.Context, slug string) (bool, error) {
	row := r.DB.QueryRow(ctx, `SELECT 1 FROM "WorkerNode" WHERE "slug"=$1 LIMIT 1`, slug)
	var dummy int
	if err := row.Scan(&dummy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *UserRepository) CreateWorkerNodeInvite(ctx context.Context, nodeID, inviterUserID, email, permission string, expiresAt time.Time) (*WorkerNodeInvite, error) {
	tx, err := r.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	token := strings.ReplaceAll(uuid.NewString(), "-", "")

	if _, err := tx.Exec(ctx, `
		DELETE FROM "WorkerNodeInvite"
		WHERE "nodeId"=$1
		  AND LOWER("email")=LOWER($2)
		  AND "acceptedAt" IS NULL
	`, nodeID, normalizedEmail); err != nil {
		return nil, err
	}

	id := uuid.NewString()
	row := tx.QueryRow(ctx, `
		INSERT INTO "WorkerNodeInvite"
		("id","nodeId","inviterUserId","email","permission","token","expiresAt")
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING "id","nodeId","inviterUserId","email","permission","token","expiresAt","acceptedAt","createdAt","updatedAt"
	`, id, nodeID, inviterUserID, normalizedEmail, permission, token, expiresAt)

	invite, err := scanWorkerNodeInvite(row)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return invite, nil
}

func (r *UserRepository) ListPendingWorkerNodeInvitesForNode(ctx context.Context, nodeID string) ([]WorkerNodeInvite, error) {
	rows, err := r.DB.Query(ctx, `
		SELECT
			i."id",
			i."nodeId",
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
		FROM "WorkerNodeInvite" i
		INNER JOIN "WorkerNode" n ON n."id"=i."nodeId"
		INNER JOIN "User" u ON u."id"=i."inviterUserId"
		WHERE i."nodeId"=$1
		  AND i."acceptedAt" IS NULL
		  AND i."expiresAt" > NOW()
		ORDER BY i."createdAt" DESC
	`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var invites []WorkerNodeInvite
	for rows.Next() {
		invite, err := scanWorkerNodeInviteWithNode(rows)
		if err != nil {
			return nil, err
		}
		invites = append(invites, *invite)
	}
	return invites, rows.Err()
}

func (r *UserRepository) ListIncomingWorkerNodeInvites(ctx context.Context, email string) ([]WorkerNodeInvite, error) {
	normalizedEmail := strings.ToLower(strings.TrimSpace(email))
	rows, err := r.DB.Query(ctx, `
		SELECT
			i."id",
			i."nodeId",
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
		FROM "WorkerNodeInvite" i
		INNER JOIN "WorkerNode" n ON n."id"=i."nodeId"
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

	var invites []WorkerNodeInvite
	for rows.Next() {
		invite, err := scanWorkerNodeInviteWithNode(rows)
		if err != nil {
			return nil, err
		}
		invites = append(invites, *invite)
	}
	return invites, rows.Err()
}

func (r *UserRepository) RevokeWorkerNodeInvite(ctx context.Context, nodeID, inviteID string) (bool, error) {
	tag, err := r.DB.Exec(ctx, `
		DELETE FROM "WorkerNodeInvite"
		WHERE "id"=$1
		  AND "nodeId"=$2
		  AND "acceptedAt" IS NULL
	`, inviteID, nodeID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *UserRepository) ListWorkerNodeGuests(ctx context.Context, nodeID string) ([]WorkerNodeGuest, error) {
	rows, err := r.DB.Query(ctx, `
		SELECT
			g."nodeId",
			n."name",
			n."slug",
			u."id",
			u."name",
			u."email",
			g."permission",
			g."createdAt"
		FROM "WorkerNodeGuest" g
		INNER JOIN "WorkerNode" n ON n."id"=g."nodeId"
		INNER JOIN "User" u ON u."id"=g."userId"
		WHERE g."nodeId"=$1
		ORDER BY g."createdAt" ASC
	`, nodeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var guests []WorkerNodeGuest
	for rows.Next() {
		guest, err := scanWorkerNodeGuest(rows)
		if err != nil {
			return nil, err
		}
		guests = append(guests, *guest)
	}
	return guests, rows.Err()
}

func (r *UserRepository) RemoveWorkerNodeGuest(ctx context.Context, nodeID, userID string) (bool, error) {
	tag, err := r.DB.Exec(ctx, `
		DELETE FROM "WorkerNodeGuest"
		WHERE "nodeId"=$1
		  AND "userId"=$2
	`, nodeID, userID)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

func (r *UserRepository) AcceptWorkerNodeInvite(ctx context.Context, inviteID, userID, email string) (*WorkerNode, error) {
	tx, err := r.DB.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	normalizedEmail := strings.ToLower(strings.TrimSpace(email))

	var (
		nodeID     string
		permission string
		expiresAt  time.Time
		acceptedAt sql.NullTime
	)

	if err := tx.QueryRow(ctx, `
		SELECT "nodeId","permission","expiresAt","acceptedAt"
		FROM "WorkerNodeInvite"
		WHERE "id"=$1
		  AND LOWER("email")=LOWER($2)
		FOR UPDATE
	`, inviteID, normalizedEmail).Scan(&nodeID, &permission, &expiresAt, &acceptedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if acceptedAt.Valid || expiresAt.Before(time.Now()) {
		return nil, nil
	}

	now := time.Now()
	if _, err := tx.Exec(ctx, `
		UPDATE "WorkerNodeInvite"
		SET "acceptedAt"=$1
		WHERE "id"=$2
	`, now, inviteID); err != nil {
		return nil, err
	}

	guestID := uuid.NewString()
	if _, err := tx.Exec(ctx, `
		INSERT INTO "WorkerNodeGuest" ("id","nodeId","userId","permission")
		VALUES ($1,$2,$3,$4)
		ON CONFLICT ("nodeId","userId")
		DO UPDATE SET "permission"=EXCLUDED."permission"
	`, guestID, nodeID, userID, permission); err != nil {
		return nil, err
	}

	row := tx.QueryRow(ctx, `
		SELECT
			n."id",
			n."slug",
			n."name",
			n."baseUrl",
			n."apiKey",
			n."ownerUserId",
			CASE
				WHEN n."ownerUserId"=$1 THEN 'owner'
				ELSE COALESCE(g."permission", 'viewer')
			END AS "accessRole",
			n."createdAt",
			n."updatedAt"
		FROM "WorkerNode" n
		LEFT JOIN "WorkerNodeGuest" g
			ON g."nodeId"=n."id" AND g."userId"=$1
		WHERE n."id"=$2
		LIMIT 1
	`, userID, nodeID)

	node, err := scanWorkerNodeWithAccess(row)
	if err != nil {
		return nil, err
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return node, nil
}

func scanWorkerNode(row pgx.Row) (*WorkerNode, error) {
	var node WorkerNode
	if err := row.Scan(
		&node.ID,
		&node.Slug,
		&node.Name,
		&node.BaseURL,
		&node.APIKey,
		&node.OwnerUserID,
		&node.CreatedAt,
		&node.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &node, nil
}

func scanWorkerNodeWithAccess(row pgx.Row) (*WorkerNode, error) {
	var node WorkerNode
	if err := row.Scan(
		&node.ID,
		&node.Slug,
		&node.Name,
		&node.BaseURL,
		&node.APIKey,
		&node.OwnerUserID,
		&node.AccessRole,
		&node.CreatedAt,
		&node.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &node, nil
}

func scanWorkerNodeInvite(row pgx.Row) (*WorkerNodeInvite, error) {
	var (
		invite     WorkerNodeInvite
		acceptedAt sql.NullTime
	)
	if err := row.Scan(
		&invite.ID,
		&invite.NodeID,
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

func scanWorkerNodeInviteWithNode(row pgx.Row) (*WorkerNodeInvite, error) {
	var (
		invite     WorkerNodeInvite
		acceptedAt sql.NullTime
	)
	if err := row.Scan(
		&invite.ID,
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

func scanWorkerNodeGuest(row pgx.Row) (*WorkerNodeGuest, error) {
	var (
		guest WorkerNodeGuest
		name  sql.NullString
	)
	if err := row.Scan(
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
