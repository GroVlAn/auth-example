package repository

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/GroVlAn/auth-example/internal/core/e"
	"github.com/jmoiron/sqlx"
)

func handleQueryError(err error, msg string) error {
	if errors.Is(err, sql.ErrNoRows) {
		return e.NewErrNotFound(
			err,
			msg,
		)
	}

	return e.NewErrInternal(
		err,
	)
}

func withTx(ctx context.Context, db *sqlx.DB, fn func(*sqlx.Tx) error) error {
	tx, err := db.BeginTxx(ctx, nil)
	if err != nil {
		return e.NewErrInternal(fmt.Errorf("begin tx: %w", err))
	}
	defer tx.Rollback()

	if err := fn(tx); err != nil {
		return err
	}

	return tx.Commit()
}
