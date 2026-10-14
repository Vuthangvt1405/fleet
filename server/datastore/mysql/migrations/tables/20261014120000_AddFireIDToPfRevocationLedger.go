package tables

import (
	"database/sql"
	"fmt"
)

func init() {
	MigrationClient.AddMigration(Up_20261014120000, Down_20261014120000)
}

func Up_20261014120000(tx *sql.Tx) error {
	_, err := tx.Exec(`ALTER TABLE pf_revocation_ledger ADD COLUMN fire_id varchar(36) COLLATE utf8mb4_unicode_ci DEFAULT NULL AFTER cve`)
	if err != nil {
		return fmt.Errorf("adding fire_id to pf_revocation_ledger: %w", err)
	}
	return nil
}

func Down_20261014120000(tx *sql.Tx) error {
	return nil
}
