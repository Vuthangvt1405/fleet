package tables

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestUp_20261009120000(t *testing.T) {
	db := applyUpToPrev(t)

	applyNext(t, db)

	// Pending discovery row: webhook accepted (202 + task_key) but PF event
	// not yet confirmed via search.
	_, err := db.Exec(`
		INSERT INTO pf_revocation_ledger (
			host_id, host_mac, trigger_type, policy_id, cve,
			pf_event_type, pf_event_id, pf_task_key, fired_at, state
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW(6), ?)`,
		42, "aa:bb:cc:dd:ee:ff", "policy", 7, nil,
		"3500001", nil, "task-key-1", "pending_discovery",
	)
	require.NoError(t, err)

	// Active row sharing the same group key: same MAC + PF type, different
	// policy. Both must resolve before the group may close.
	_, err = db.Exec(`
		INSERT INTO pf_revocation_ledger (
			host_id, host_mac, trigger_type, policy_id, cve,
			pf_event_type, pf_event_id, fired_at, state, clean_checks,
			last_counted_observation_id
		) VALUES (?, ?, ?, ?, ?, ?, ?, NOW(6), ?, ?, ?)`,
		42, "aa:bb:cc:dd:ee:ff", "policy", 8, nil,
		"3500001", "12345", "active", 1, "eval-1",
	)
	require.NoError(t, err)

	var (
		state       string
		clean       int
		observation *string
	)
	err = db.QueryRow(`
		SELECT state, clean_checks, last_counted_observation_id
		FROM pf_revocation_ledger
		WHERE host_id = ? AND policy_id = ?`, 42, 8).Scan(&state, &clean, &observation)
	require.NoError(t, err)
	require.Equal(t, "active", state)
	require.Equal(t, 1, clean)
	require.NotNil(t, observation)
	require.Equal(t, "eval-1", *observation)

	// Group lookup by (host_mac, pf_event_type) must return both findings.
	var count int
	err = db.QueryRow(`
		SELECT COUNT(*) FROM pf_revocation_ledger
		WHERE host_mac = ? AND pf_event_type = ?`, "aa:bb:cc:dd:ee:ff", "3500001").Scan(&count)
	require.NoError(t, err)
	require.Equal(t, 2, count)
}
