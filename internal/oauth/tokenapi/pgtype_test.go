//go:build integration

package tokenapi_test

import (
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// pgtypeUUID converts a google uuid to a pgtype.UUID; tiny helper shared by
// the CIBA test for the ListPendingCIBAForUser params.
func pgtypeUUID(u uuid.UUID) pgtype.UUID {
	if u == uuid.Nil {
		return pgtype.UUID{}
	}
	return pgtype.UUID{Bytes: u, Valid: true}
}
