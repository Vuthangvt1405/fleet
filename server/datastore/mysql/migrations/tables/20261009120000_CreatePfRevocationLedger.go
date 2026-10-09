package tables

import (
	"database/sql"
	"fmt"
)

func init() {
	MigrationClient.AddMigration(Up_20261009120000, Down_20261009120000)
}

// Up_20261009120000 creates pf_revocation_ledger, the single-table Fleet
// finding ledger for PacketFence event revocation (v1).
//
// One row per Fleet finding (failed policy or CVE), grouped by
// (host_mac, pf_event_type) at the application layer. All close decisions and
// state transitions for a group must be performed atomically for the entire
// group; PacketFence closes all non-closed rows for (mac, event type), so a
// per-row close is unsafe when findings share a type.
//
// States: pending_discovery, active, clearing, cleared, ownership_blocked.
// A 202 webhook accept is recorded as pending_discovery until the worker
// confirms via security_events/search that PacketFence created the event.
func Up_20261009120000(tx *sql.Tx) error {
	_, err := tx.Exec(`
CREATE TABLE pf_revocation_ledger (
  id                            bigint unsigned NOT NULL AUTO_INCREMENT,
  host_id                       bigint unsigned NOT NULL,
  host_mac                      varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  trigger_type                  varchar(16) COLLATE utf8mb4_unicode_ci NOT NULL,
  policy_id                     bigint unsigned DEFAULT NULL,
  cve                           varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  pf_event_type                 varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL,
  pf_event_id                   varchar(64) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  pf_task_key                   varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  fired_at                      datetime(6) NOT NULL,
  state                         varchar(32) COLLATE utf8mb4_unicode_ci NOT NULL DEFAULT 'pending_discovery',
  clean_checks                  int NOT NULL DEFAULT 0,
  last_counted_observation_id   varchar(128) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  last_observation_at           datetime(6) DEFAULT NULL,
  next_retry_at                 datetime(6) DEFAULT NULL,
  last_error                    text COLLATE utf8mb4_unicode_ci,
  ownership_block_reason        varchar(255) COLLATE utf8mb4_unicode_ci DEFAULT NULL,
  created_at                    datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
  updated_at                    datetime(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
  PRIMARY KEY (id),
  KEY idx_pf_ledger_group (host_mac, pf_event_type, state),
  KEY idx_pf_ledger_host (host_id),
  KEY idx_pf_ledger_retry (state, next_retry_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
`)
	if err != nil {
		return fmt.Errorf("creating pf_revocation_ledger table: %w", err)
	}
	return nil
}

func Down_20261009120000(tx *sql.Tx) error {
	return nil
}
