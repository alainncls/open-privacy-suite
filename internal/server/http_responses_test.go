package server

import (
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/assert"
)

func TestIsForeignKeyViolation(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23503"}
	assert.True(t, isForeignKeyViolation(pgErr))
	assert.False(t, isForeignKeyViolation(errors.New("some other error")))
	assert.False(t, isForeignKeyViolation(&pgconn.PgError{Code: "23505"}))
}

func TestIsUniqueViolation(t *testing.T) {
	pgErr := &pgconn.PgError{Code: "23505"}
	assert.True(t, isUniqueViolation(pgErr))
	assert.False(t, isUniqueViolation(errors.New("some other error")))
	assert.False(t, isUniqueViolation(&pgconn.PgError{Code: "23503"}))
}
