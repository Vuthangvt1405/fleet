package tables

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUp_20261014120000(t *testing.T) {
	db := applyUpToPrev(t)
	applyNext(t, db)

	var count int
	err := db.QueryRow(`
		SELECT COUNT(*) FROM information_schema.columns
		WHERE table_schema = DATABASE()
		  AND table_name = 'pf_revocation_ledger'
		  AND column_name = 'fire_id'
		  AND is_nullable = 'YES'
	`).Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 1, count)
}
