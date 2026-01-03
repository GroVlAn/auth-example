package repository

import (
	"context"
	"fmt"

	"github.com/GroVlAn/auth-example/internal/core"
	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/jmoiron/sqlx"
)

const (
	tableAccessToken        = "access_token"
	tableRefreshToken       = "refresh_token"
	tableAccessRefreshToken = "access_refresh_token"
)

type AuthRepository struct {
	db *sqlx.DB
}

func NewAuthRepository(db *sqlx.DB) *AuthRepository {
	return &AuthRepository{
		db: db,
	}
}

func (ur *AuthRepository) CreateTokens(
	ctx context.Context,
	accToken core.AccessToken,
	rfToken core.RefreshToken,
	artID string,
) error {
	return withTx(ctx, ur.db, func(tx *sqlx.Tx) error {
		internalError := func(msg string, err error) error {
			return e.NewErrInternal(
				fmt.Errorf("%s: %w", msg, err),
			)
		}

		queryCreateRefreshToken := fmt.Sprintf(
			"INSERT INTO %s (id, token, start_ttl, end_ttl, user_id) VALUES (:id, :token, :start_ttl, :end_ttl, :user_id)",
			tableRefreshToken,
		)

		_, err := tx.NamedExecContext(ctx, queryCreateRefreshToken, rfToken)
		if err != nil {
			return internalError("creating refresh token", err)
		}

		queryCreateAccessToken := fmt.Sprintf(
			"INSERT INTO %s (id, token, start_ttl, end_ttl, user_id) VALUES (:id, :token, :start_ttl, :end_ttl, :user_id)",
			tableAccessToken,
		)

		_, err = tx.NamedExecContext(ctx, queryCreateAccessToken, accToken)
		if err != nil {
			return internalError("creating access token", err)
		}

		queryCreateAccessRefreshToken := fmt.Sprintf(
			"INSERT INTO %s (id, refresh_token_id, access_token_id) VALUES ($1, $2, $3)",
			tableAccessRefreshToken,
		)

		_, err = tx.ExecContext(ctx, queryCreateAccessRefreshToken,
			artID,
			rfToken.ID,
			accToken.ID,
		)
		if err != nil {
			return internalError("creating access-refresh token", err)
		}

		return nil
	})
}

func (ur *AuthRepository) CreateAccessToken(ctx context.Context, token core.AccessToken) error {
	query := fmt.Sprintf(
		"INSERT INTO %s (id, token, start_ttl, end_ttl, user_id) VALUES (:id, :token, :start_ttl, :end_ttl, :user_id)",
		tableAccessToken,
	)

	_, err := ur.db.NamedExecContext(ctx, query, token)
	if err != nil {
		return e.NewErrInternal(
			fmt.Errorf("creating access token: %w", err),
		)
	}

	return nil
}

func (ur *AuthRepository) AccessToken(ctx context.Context, token string) (core.AccessToken, error) {
	query := fmt.Sprintf(
		"SELECT id, token, start_ttl, end_ttl, user_id FROM %s WHERE token = $1",
		tableAccessToken,
	)

	var accessToken core.AccessToken

	err := ur.db.GetContext(ctx, &accessToken, query, token)
	if err != nil {
		return core.AccessToken{}, handleQueryError(
			fmt.Errorf("getting access token: %w", err),
			"access token not exist",
		)
	}

	return accessToken, nil
}

func (ur *AuthRepository) DeleteAllAccessTokens(ctx context.Context, userID string) error {
	queryDeleteAllTokens := fmt.Sprintf(
		"DELETE FROM %s WHERE user_id = $1",
		tableAccessToken,
	)

	if _, err := ur.db.ExecContext(ctx, queryDeleteAllTokens, userID); err != nil {
		return e.NewErrInternal(
			fmt.Errorf("deleting all access tokens: %w", err),
		)
	}

	return nil
}

func (ur *AuthRepository) DeleteAccessToken(ctx context.Context, token string) error {
	queryDeleteAccessToken := fmt.Sprintf(
		"DELETE FROM %s WHERE token = $1",
		tableAccessToken,
	)

	if _, err := ur.db.ExecContext(ctx, queryDeleteAccessToken, token); err != nil {
		return e.NewErrInternal(
			fmt.Errorf("deleting access token: %w", err),
		)
	}

	return nil
}

func (ur *AuthRepository) RefreshToken(ctx context.Context, token string) (core.RefreshToken, error) {
	query := fmt.Sprintf(
		"SELECT * FROM %s WHERE token = $1",
		tableRefreshToken,
	)

	var refreshToken core.RefreshToken

	err := ur.db.GetContext(ctx, &refreshToken, query, token)
	if err != nil {
		return core.RefreshToken{}, handleQueryError(
			fmt.Errorf("getting refresh token: %w", err),
			"refresh token not exist",
		)
	}

	return refreshToken, nil
}

func (ur *AuthRepository) DeleteAllRefreshTokens(ctx context.Context, userID string) error {
	queryDeleteAllTokens := fmt.Sprintf(
		"DELETE FROM %s WHERE user_id = $1",
		tableRefreshToken,
	)

	if _, err := ur.db.ExecContext(ctx, queryDeleteAllTokens, userID); err != nil {
		return e.NewErrInternal(
			fmt.Errorf("deleting all refresh tokens: %w", err),
		)
	}

	return nil
}

func (ur *AuthRepository) DeleteRefreshToken(ctx context.Context, token string) error {
	queryDeleteRefreshToken := fmt.Sprintf(
		"DELETE FROM %s WHERE token = $1",
		tableRefreshToken,
	)

	if _, err := ur.db.ExecContext(ctx, queryDeleteRefreshToken, token); err != nil {
		return e.NewErrInternal(
			fmt.Errorf("deleting refresh token: %w", err),
		)
	}

	return nil
}
