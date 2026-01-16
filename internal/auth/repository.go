package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type UserRepository struct {
	DB *pgxpool.Pool
}

type OAuthAccount struct {
	ID                string
	UserID            string
	Provider          string
	ProviderAccountID string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

func NewUserRepository(db *pgxpool.Pool) *UserRepository {
	return &UserRepository{DB: db}
}

func (r *UserRepository) Create(ctx context.Context, name *string, email string, passwordHash *string, verified *time.Time) (*User, error) {
	id := uuid.NewString()

	query := `
		INSERT INTO "User"
		("id","name","email","password","emailVerified","role","theme")
		VALUES ($1,$2,$3,$4,$5,$6,$7)
		RETURNING "id","name","email","emailVerified","password","image","theme","twoFactorSecret","isTwoFactorEnabled","twoFactorMethod","twoFactorEmailCode","twoFactorCodeExpires","passwordResetToken","passwordResetExpires","role","createdAt","updatedAt"
	`

	row := r.DB.QueryRow(ctx, query, id, name, email, passwordHash, verified, "USER", "system")
	return scanUser(row)
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*User, error) {
	query := `
		SELECT "id","name","email","emailVerified","password","image","theme","twoFactorSecret","isTwoFactorEnabled","twoFactorMethod","twoFactorEmailCode","twoFactorCodeExpires","passwordResetToken","passwordResetExpires","role","createdAt","updatedAt"
		FROM "User"
		WHERE "email"=$1
	`
	row := r.DB.QueryRow(ctx, query, email)
	user, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return user, err
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (*User, error) {
	query := `
		SELECT "id","name","email","emailVerified","password","image","theme","twoFactorSecret","isTwoFactorEnabled","twoFactorMethod","twoFactorEmailCode","twoFactorCodeExpires","passwordResetToken","passwordResetExpires","role","createdAt","updatedAt"
		FROM "User"
		WHERE "id"=$1
	`
	row := r.DB.QueryRow(ctx, query, id)
	user, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return user, err
}

func (r *UserRepository) SetEmailVerified(ctx context.Context, userID string) error {
	_, err := r.DB.Exec(ctx, `UPDATE "User" SET "emailVerified"=NOW() WHERE "id"=$1`, userID)
	return err
}

func (r *UserRepository) DeleteVerificationTokens(ctx context.Context, userID string) error {
	_, err := r.DB.Exec(ctx, `DELETE FROM "VerificationToken" WHERE "userId"=$1`, userID)
	return err
}

func (r *UserRepository) CreateVerificationToken(ctx context.Context, userID, token string, expires time.Time) (*VerificationToken, error) {
	id := uuid.NewString()
	hashed := HashString(token)
	_, err := r.DB.Exec(ctx, `
		INSERT INTO "VerificationToken" ("id","token","expires","userId")
		VALUES ($1,$2,$3,$4)
	`, id, hashed, expires, userID)
	if err != nil {
		return nil, err
	}
	return &VerificationToken{ID: id, Token: token, Expires: expires, UserID: userID}, nil
}

func (r *UserRepository) GetVerificationToken(ctx context.Context, email, token string) (*VerificationToken, *User, error) {
	user, err := r.FindByEmail(ctx, email)
	if err != nil || user == nil {
		return nil, user, err
	}

	row := r.DB.QueryRow(ctx, `
		SELECT "id","token","expires"
		FROM "VerificationToken"
		WHERE "userId"=$1 AND "token"=$2 AND "expires" > NOW()
	`, user.ID, HashString(token))

	var vt VerificationToken
	vt.UserID = user.ID
	if err := row.Scan(&vt.ID, &vt.Token, &vt.Expires); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, user, nil
		}
		return nil, nil, err
	}

	return &vt, user, nil
}

func (r *UserRepository) UpdateTwoFactorSecret(ctx context.Context, userID, method string, secret *string) error {
	_, err := r.DB.Exec(ctx, `
		UPDATE "User"
		SET "twoFactorSecret"=$1, "twoFactorMethod"=$2, "twoFactorEmailCode"=NULL, "twoFactorCodeExpires"=NULL
		WHERE "id"=$3
	`, secret, method, userID)
	return err
}

func (r *UserRepository) SaveEmailCode(ctx context.Context, userID, code string, expires time.Time) error {
	var hashed interface{}
	var expiry interface{}
	if code != "" {
		hashed = HashString(code)
		expiry = expires
	}
	_, err := r.DB.Exec(ctx, `
		UPDATE "User"
		SET "twoFactorEmailCode"=$1, "twoFactorCodeExpires"=$2, "twoFactorMethod"='email'
		WHERE "id"=$3
	`, hashed, expiry, userID)
	return err
}

func (r *UserRepository) ClearEmailCode(ctx context.Context, userID string) error {
	_, err := r.DB.Exec(ctx, `
		UPDATE "User"
		SET "twoFactorEmailCode"=NULL, "twoFactorCodeExpires"=NULL
		WHERE "id"=$1
	`, userID)
	return err
}

func (r *UserRepository) EnableTwoFactor(ctx context.Context, userID string) error {
	_, err := r.DB.Exec(ctx, `
		UPDATE "User"
		SET "isTwoFactorEnabled"=TRUE,
		    "twoFactorEmailCode"=NULL,
		    "twoFactorCodeExpires"=NULL
		WHERE "id"=$1
	`, userID)
	return err
}

func (r *UserRepository) DisableTwoFactor(ctx context.Context, userID string) error {
	_, err := r.DB.Exec(ctx, `
		UPDATE "User"
		SET "isTwoFactorEnabled"=FALSE,
		    "twoFactorSecret"=NULL,
		    "twoFactorMethod"=NULL,
		    "twoFactorEmailCode"=NULL,
		    "twoFactorCodeExpires"=NULL
		WHERE "id"=$1
	`, userID)
	return err
}

func (r *UserRepository) UpdateProfile(ctx context.Context, userID string, name *string, theme *string) (*User, error) {
	sets := []string{}
	args := []interface{}{}
	idx := 1

	if name != nil {
		sets = append(sets, fmt.Sprintf(`"name"=$%d`, idx))
		args = append(args, name)
		idx++
	}
	if theme != nil {
		sets = append(sets, fmt.Sprintf(`"theme"=$%d`, idx))
		args = append(args, theme)
		idx++
	}

	if len(sets) == 0 {
		return r.FindByID(ctx, userID)
	}

	args = append(args, userID)
	query := fmt.Sprintf(`
		UPDATE "User"
		SET %s
		WHERE "id"=$%d
		RETURNING "id","name","email","emailVerified","password","image","theme","twoFactorSecret","isTwoFactorEnabled","twoFactorMethod","twoFactorEmailCode","twoFactorCodeExpires","passwordResetToken","passwordResetExpires","role","createdAt","updatedAt"
	`, strings.Join(sets, ","), idx)

	row := r.DB.QueryRow(ctx, query, args...)
	return scanUser(row)
}

func (r *UserRepository) UpdateEmail(ctx context.Context, userID, email string) (*User, error) {
	row := r.DB.QueryRow(ctx, `
		UPDATE "User"
		SET "email"=$1,
		    "emailVerified"=NULL
		WHERE "id"=$2
		RETURNING "id","name","email","emailVerified","password","image","theme","twoFactorSecret","isTwoFactorEnabled","twoFactorMethod","twoFactorEmailCode","twoFactorCodeExpires","passwordResetToken","passwordResetExpires","role","createdAt","updatedAt"
	`, email, userID)
	return scanUser(row)
}

func (r *UserRepository) UpdatePassword(ctx context.Context, userID, hashed string) error {
	_, err := r.DB.Exec(ctx, `
		UPDATE "User"
		SET "password"=$1,
		    "passwordResetToken"=NULL,
		    "passwordResetExpires"=NULL
		WHERE "id"=$2
	`, hashed, userID)
	return err
}

func (r *UserRepository) SetPasswordReset(ctx context.Context, userID, hashedToken string, expires time.Time) error {
	_, err := r.DB.Exec(ctx, `
		UPDATE "User"
		SET "passwordResetToken"=$1,
		    "passwordResetExpires"=$2
		WHERE "id"=$3
	`, hashedToken, expires, userID)
	return err
}

func (r *UserRepository) ClearPasswordReset(ctx context.Context, userID string) error {
	_, err := r.DB.Exec(ctx, `
		UPDATE "User"
		SET "passwordResetToken"=NULL,
		    "passwordResetExpires"=NULL
		WHERE "id"=$1
	`, userID)
	return err
}

func (r *UserRepository) FindUserWithResetToken(ctx context.Context, token string) (*User, error) {
	rows, err := r.DB.Query(ctx, `
		SELECT "id","name","email","emailVerified","password","image","theme","twoFactorSecret","isTwoFactorEnabled","twoFactorMethod","twoFactorEmailCode","twoFactorCodeExpires","passwordResetToken","passwordResetExpires","role","createdAt","updatedAt"
		FROM "User"
		WHERE "passwordResetToken" IS NOT NULL AND "passwordResetExpires" > NOW()
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		if user.PasswordResetToken != nil && bcrypt.CompareHashAndPassword([]byte(*user.PasswordResetToken), []byte(token)) == nil {
			return user, nil
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return nil, nil
}

func (r *UserRepository) UpdateImage(ctx context.Context, userID, imagePath string) (*User, error) {
	row := r.DB.QueryRow(ctx, `
		UPDATE "User"
		SET "image"=$1
		WHERE "id"=$2
		RETURNING "id","name","email","emailVerified","password","image","theme","twoFactorSecret","isTwoFactorEnabled","twoFactorMethod","twoFactorEmailCode","twoFactorCodeExpires","passwordResetToken","passwordResetExpires","role","createdAt","updatedAt"
	`, imagePath, userID)
	return scanUser(row)
}

func (r *UserRepository) DeleteUser(ctx context.Context, userID string) error {
	_, err := r.DB.Exec(ctx, `DELETE FROM "User" WHERE "id"=$1`, userID)
	return err
}

func (r *UserRepository) FindByOAuth(ctx context.Context, provider, accountID string) (*User, error) {
	query := `
		SELECT u."id",u."name",u."email",u."emailVerified",u."password",u."image",u."theme",u."twoFactorSecret",u."isTwoFactorEnabled",u."twoFactorMethod",u."twoFactorEmailCode",u."twoFactorCodeExpires",u."passwordResetToken",u."passwordResetExpires",u."role",u."createdAt",u."updatedAt"
		FROM "User" u
		INNER JOIN "OAuthAccount" oa ON oa."userId" = u."id"
		WHERE oa."provider"=$1 AND oa."providerAccountId"=$2
	`
	row := r.DB.QueryRow(ctx, query, provider, accountID)
	user, err := scanUser(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return user, err
}

func (r *UserRepository) LinkOAuthAccount(ctx context.Context, userID, provider, accountID string) (*OAuthAccount, error) {
	id := uuid.NewString()
	now := time.Now()
	row := r.DB.QueryRow(ctx, `
		INSERT INTO "OAuthAccount"
		("id","userId","provider","providerAccountId","createdAt","updatedAt")
		VALUES ($1,$2,$3,$4,$5,$6)
		ON CONFLICT ("provider","providerAccountId") DO UPDATE SET "userId"=EXCLUDED."userId","updatedAt"=EXCLUDED."updatedAt"
		RETURNING "id","userId","provider","providerAccountId","createdAt","updatedAt"
	`, id, userID, provider, accountID, now, now)

	var oa OAuthAccount
	if err := row.Scan(&oa.ID, &oa.UserID, &oa.Provider, &oa.ProviderAccountID, &oa.CreatedAt, &oa.UpdatedAt); err != nil {
		return nil, err
	}
	return &oa, nil
}

func (r *UserRepository) HasOAuthAccount(ctx context.Context, userID string) (bool, error) {
	row := r.DB.QueryRow(ctx, `
		SELECT 1 FROM "OAuthAccount" WHERE "userId"=$1 LIMIT 1
	`, userID)
	var dummy int
	if err := row.Scan(&dummy); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (r *UserRepository) CreatePasskey(ctx context.Context, cred PasskeyCredential) (*PasskeyCredential, error) {
	id := uuid.NewString()
	now := time.Now()
	transport := strings.Join(cred.Transports, ",")
	row := r.DB.QueryRow(ctx, `
		INSERT INTO "PasskeyCredential"
		("id","userId","credentialId","publicKey","attestationType","aaguid","transports","signCount","label","createdAt","updatedAt")
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
		RETURNING "id","userId","credentialId","publicKey","attestationType","aaguid","transports","signCount","label","createdAt","updatedAt"
	`, id, cred.UserID, cred.CredentialID, cred.PublicKey, cred.AttestationType, cred.AAGUID, transport, cred.SignCount, cred.Label, now, now)
	return scanPasskey(row)
}

func (r *UserRepository) ListPasskeys(ctx context.Context, userID string) ([]PasskeyCredential, error) {
	rows, err := r.DB.Query(ctx, `
		SELECT "id","userId","credentialId","publicKey","attestationType","aaguid","transports","signCount","label","createdAt","updatedAt"
		FROM "PasskeyCredential"
		WHERE "userId"=$1
		ORDER BY "createdAt" DESC
	`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var creds []PasskeyCredential
	for rows.Next() {
		cred, err := scanPasskey(rows)
		if err != nil {
			return nil, err
		}
		creds = append(creds, *cred)
	}
	return creds, rows.Err()
}

func (r *UserRepository) DeletePasskey(ctx context.Context, userID, passkeyID string) error {
	_, err := r.DB.Exec(ctx, `DELETE FROM "PasskeyCredential" WHERE "id"=$1 AND "userId"=$2`, passkeyID, userID)
	return err
}

func (r *UserRepository) GetPasskeyByCredentialID(ctx context.Context, credID []byte) (*PasskeyCredential, error) {
	row := r.DB.QueryRow(ctx, `
		SELECT "id","userId","credentialId","publicKey","attestationType","aaguid","transports","signCount","label","createdAt","updatedAt"
		FROM "PasskeyCredential"
		WHERE "credentialId"=$1
	`, credID)
	cred, err := scanPasskey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return cred, err
}

func (r *UserRepository) UpdatePasskeySignCount(ctx context.Context, id string, signCount uint32) error {
	_, err := r.DB.Exec(ctx, `
		UPDATE "PasskeyCredential"
		SET "signCount"=$1, "updatedAt"=NOW()
		WHERE "id"=$2
	`, signCount, id)
	return err
}

func scanUser(row pgx.Row) (*User, error) {
	var (
		id                   string
		name                 sql.NullString
		email                string
		emailVerified        sql.NullTime
		password             sql.NullString
		image                sql.NullString
		theme                sql.NullString
		twoFactorSecret      sql.NullString
		twoFactorEnabled     bool
		twoFactorMethod      sql.NullString
		twoFactorEmailCode   sql.NullString
		twoFactorCodeExpires sql.NullTime
		passwordResetToken   sql.NullString
		passwordResetExpires sql.NullTime
		role                 string
		createdAt            time.Time
		updatedAt            time.Time
	)

	if err := row.Scan(
		&id,
		&name,
		&email,
		&emailVerified,
		&password,
		&image,
		&theme,
		&twoFactorSecret,
		&twoFactorEnabled,
		&twoFactorMethod,
		&twoFactorEmailCode,
		&twoFactorCodeExpires,
		&passwordResetToken,
		&passwordResetExpires,
		&role,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}

	return &User{
		ID:                   id,
		Name:                 nullStringPtr(name),
		Email:                email,
		EmailVerified:        nullTimePtr(emailVerified),
		PasswordHash:         nullStringPtr(password),
		Image:                nullStringPtr(image),
		Theme:                stringOrDefault(theme, "system"),
		TwoFactorSecret:      nullStringPtr(twoFactorSecret),
		TwoFactorEnabled:     twoFactorEnabled,
		TwoFactorMethod:      nullStringPtr(twoFactorMethod),
		TwoFactorEmailCode:   nullStringPtr(twoFactorEmailCode),
		TwoFactorCodeExpires: nullTimePtr(twoFactorCodeExpires),
		PasswordResetToken:   nullStringPtr(passwordResetToken),
		PasswordResetExpires: nullTimePtr(passwordResetExpires),
		Role:                 role,
		CreatedAt:            createdAt,
		UpdatedAt:            updatedAt,
	}, nil
}

func nullStringPtr(ns sql.NullString) *string {
	if ns.Valid {
		return &ns.String
	}
	return nil
}

func nullTimePtr(nt sql.NullTime) *time.Time {
	if nt.Valid {
		return &nt.Time
	}
	return nil
}

func stringOrDefault(ns sql.NullString, def string) string {
	if ns.Valid {
		return ns.String
	}
	return def
}

func scanPasskey(row pgx.Row) (*PasskeyCredential, error) {
	var (
		id              string
		userID          string
		credentialID    []byte
		publicKey       []byte
		attestationType string
		aaguid          []byte
		transports      sql.NullString
		signCount       uint32
		label           sql.NullString
		createdAt       time.Time
		updatedAt       time.Time
	)

	if err := row.Scan(&id, &userID, &credentialID, &publicKey, &attestationType, &aaguid, &transports, &signCount, &label, &createdAt, &updatedAt); err != nil {
		return nil, err
	}

	return &PasskeyCredential{
		ID:              id,
		UserID:          userID,
		CredentialID:    credentialID,
		PublicKey:       publicKey,
		AttestationType: attestationType,
		AAGUID:          aaguid,
		Transports:      parseTransports(transports.String),
		SignCount:       signCount,
		Label:           nullStringPtr(label),
		CreatedAt:       createdAt,
		UpdatedAt:       updatedAt,
	}, nil
}

func parseTransports(val string) []string {
	if val == "" {
		return nil
	}
	parts := strings.Split(val, ",")
	var res []string
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			res = append(res, t)
		}
	}
	return res
}
