package mysql

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/jmoiron/sqlx"
)

const pfLedgerColumns = `
  id, host_id, host_mac, trigger_type, policy_id, cve,
  pf_event_type, pf_event_id, pf_task_key, fired_at, state, clean_checks,
  last_counted_observation_id, last_observation_at, next_retry_at,
  last_error, ownership_block_reason, created_at, updated_at`

// FindOpenPfRevocationFinding returns the existing non-cleared ledger row for
// the same finding identity, or sql.ErrNoRows when there is none. NULL-safe
// comparison (<=>) matches nullable policy_id/cve columns.
func (ds *Datastore) FindOpenPfRevocationFinding(ctx context.Context, f *fleet.PfRevocationFinding) (*fleet.PfRevocationFinding, error) {
	const stmt = `
  SELECT` + pfLedgerColumns + `
  FROM pf_revocation_ledger
  WHERE host_id = ?
    AND trigger_type = ?
    AND policy_id <=> ?
    AND cve <=> ?
    AND pf_event_type = ?
    AND state != 'cleared'
  ORDER BY id DESC LIMIT 1`
	var out fleet.PfRevocationFinding
	err := sqlx.GetContext(ctx, ds.reader(ctx), &out, stmt,
		f.HostID, f.TriggerType, f.PolicyID, f.CVE, f.PfEventType)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// CreatePfRevocationFinding inserts a new ledger row in pending_discovery
// state. Callers should check FindOpenPfRevocationFinding first to avoid
// duplicate open rows for the same finding.
func (ds *Datastore) CreatePfRevocationFinding(ctx context.Context, f *fleet.PfRevocationFinding) (*fleet.PfRevocationFinding, error) {
	const stmt = `
  INSERT INTO pf_revocation_ledger (
    host_id, host_mac, trigger_type, policy_id, cve,
    pf_event_type, pf_event_id, pf_task_key, fired_at, state, clean_checks,
    last_counted_observation_id, last_observation_at, next_retry_at,
    last_error, ownership_block_reason
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	res, err := ds.writer(ctx).ExecContext(ctx, stmt,
		f.HostID, f.HostMAC, f.TriggerType, f.PolicyID, f.CVE,
		f.PfEventType, f.PfEventID, f.PfTaskKey, f.FiredAt, f.State, f.CleanChecks,
		f.LastCountedObservationID, f.LastObservationAt, f.NextRetryAt,
		f.LastError, f.OwnershipBlockReason)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "create pf revocation finding")
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "create pf revocation finding id")
	}
	out := *f
	out.ID = uint(id)
	return &out, nil
}

// UpsertPfRevocationFinding refreshes an existing open row for the same
// finding (new fire invalidates pending clean progress) or creates one.
func (ds *Datastore) UpsertPfRevocationFinding(ctx context.Context, f *fleet.PfRevocationFinding) (*fleet.PfRevocationFinding, error) {
	var out *fleet.PfRevocationFinding
	err := ds.withRetryTxx(ctx, func(tx sqlx.ExtContext) error {
		const sel = `
  SELECT` + pfLedgerColumns + `
  FROM pf_revocation_ledger
  WHERE host_id = ?
    AND trigger_type = ?
    AND policy_id <=> ?
    AND cve <=> ?
    AND pf_event_type = ?
    AND state != 'cleared'
  ORDER BY id DESC LIMIT 1 FOR UPDATE`
		var existing fleet.PfRevocationFinding
		err := sqlx.GetContext(ctx, tx, &existing, sel,
			f.HostID, f.TriggerType, f.PolicyID, f.CVE, f.PfEventType)
		switch {
		case err == nil:
			const upd = `
  UPDATE pf_revocation_ledger SET
    host_mac = ?, pf_task_key = ?, fired_at = ?, state = ?,
    clean_checks = 0, last_counted_observation_id = NULL,
    last_observation_at = NULL, next_retry_at = NULL, last_error = NULL,
    ownership_block_reason = NULL
  WHERE id = ?`
			state := f.State
			if state == "" {
				state = fleet.PfStatePendingDiscovery
			}
			if _, err := tx.ExecContext(ctx, upd,
				f.HostMAC, f.PfTaskKey, f.FiredAt, state, existing.ID); err != nil {
				return ctxerr.Wrap(ctx, err, "refresh pf revocation finding")
			}
			existing.HostMAC = f.HostMAC
			existing.PfTaskKey = f.PfTaskKey
			existing.FiredAt = f.FiredAt
			existing.State = state
			existing.CleanChecks = 0
			out = &existing
			return nil
		case errors.Is(err, sql.ErrNoRows):
			const ins = `
  INSERT INTO pf_revocation_ledger (
    host_id, host_mac, trigger_type, policy_id, cve,
    pf_event_type, pf_event_id, pf_task_key, fired_at, state, clean_checks,
    last_counted_observation_id, last_observation_at, next_retry_at,
    last_error, ownership_block_reason
  ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
			state := f.State
			if state == "" {
				state = fleet.PfStatePendingDiscovery
			}
			res, err := tx.ExecContext(ctx, ins,
				f.HostID, f.HostMAC, f.TriggerType, f.PolicyID, f.CVE,
				f.PfEventType, f.PfEventID, f.PfTaskKey, f.FiredAt, state, f.CleanChecks,
				f.LastCountedObservationID, f.LastObservationAt, f.NextRetryAt,
				f.LastError, f.OwnershipBlockReason)
			if err != nil {
				return ctxerr.Wrap(ctx, err, "create pf revocation finding")
			}
			id, err := res.LastInsertId()
			if err != nil {
				return ctxerr.Wrap(ctx, err, "create pf revocation finding id")
			}
			cpy := *f
			cpy.ID = uint(id)
			cpy.State = state
			out = &cpy
			return nil
		default:
			return ctxerr.Wrap(ctx, err, "find pf revocation finding")
		}
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ListPfRevocationGroup returns all non-cleared findings sharing one
// (host_mac, pf_event_type) group, oldest first. Close decisions must consider
// every row returned: one unresolved finding blocks the group.
func (ds *Datastore) ListPfRevocationGroup(ctx context.Context, hostMAC, pfEventType string) ([]*fleet.PfRevocationFinding, error) {
	const stmt = `
  SELECT` + pfLedgerColumns + `
  FROM pf_revocation_ledger
  WHERE host_mac = ? AND pf_event_type = ? AND state != 'cleared'
  ORDER BY id ASC`
	var out []*fleet.PfRevocationFinding
	if err := sqlx.SelectContext(ctx, ds.reader(ctx), &out, stmt, hostMAC, pfEventType); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "list pf revocation group")
	}
	return out, nil
}

// ListPfRevocationDue returns up to limit findings in pending_discovery,
// active, or clearing state whose retry is due, for the reconciliation worker
// to group by (host_mac, pf_event_type). Clearing rows are included so a run
// interrupted mid-close is re-validated instead of stuck.
func (ds *Datastore) ListPfRevocationDue(ctx context.Context, now time.Time, limit int) ([]*fleet.PfRevocationFinding, error) {
	if limit <= 0 {
		limit = 100
	}
	const stmt = `
  SELECT` + pfLedgerColumns + `
  FROM pf_revocation_ledger
  WHERE state IN ('pending_discovery', 'active', 'clearing')
    AND (next_retry_at IS NULL OR next_retry_at <= ?)
  ORDER BY next_retry_at IS NOT NULL, next_retry_at ASC, id ASC
  LIMIT ?`
	var out []*fleet.PfRevocationFinding
	if err := sqlx.SelectContext(ctx, ds.reader(ctx), &out, stmt, now, limit); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "list due pf revocation findings")
	}
	return out, nil
}

// UpdatePfRevocationFinding persists worker-owned mutable fields by id.
func (ds *Datastore) UpdatePfRevocationFinding(ctx context.Context, f *fleet.PfRevocationFinding) error {
	const stmt = `
  UPDATE pf_revocation_ledger SET
    pf_event_id = ?, state = ?, clean_checks = ?,
    last_counted_observation_id = ?, last_observation_at = ?,
    next_retry_at = ?, last_error = ?, ownership_block_reason = ?
  WHERE id = ?`
	_, err := ds.writer(ctx).ExecContext(ctx, stmt,
		f.PfEventID, f.State, f.CleanChecks,
		f.LastCountedObservationID, f.LastObservationAt,
		f.NextRetryAt, f.LastError, f.OwnershipBlockReason, f.ID)
	return ctxerr.Wrap(ctx, err, "update pf revocation finding")
}

// MarkPfRevocationGroupState transitions every non-cleared row in a group to
// the given state. Rows affected is returned so callers can detect a race
// where a new finding landed mid-close.
func (ds *Datastore) MarkPfRevocationGroupState(ctx context.Context, hostMAC, pfEventType, toState string) (int64, error) {
	const stmt = `
  UPDATE pf_revocation_ledger
  SET state = ?, next_retry_at = NULL, last_error = NULL
  WHERE host_mac = ? AND pf_event_type = ? AND state != 'cleared'`
	res, err := ds.writer(ctx).ExecContext(ctx, stmt, toState, hostMAC, pfEventType)
	if err != nil {
		return 0, ctxerr.Wrap(ctx, err, "mark pf revocation group")
	}
	return res.RowsAffected()
}
