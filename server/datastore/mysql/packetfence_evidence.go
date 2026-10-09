package mysql

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

// CheckPfPolicyCompliance observes one policy finding using fresh Fleet data.
//
// It returns the host's current policy result with the host-level policy
// report timestamp (hosts.policy_updated_at) as the observation ID. Two
// worker polls reading the same report share an observation ID and count
// once. policy_membership.updated_at is deliberately NOT used: it tracks last
// state change, not last execution.
//
// MVP limitation: the observation proves a fresh host policy report showed
// this policy passing, not that this specific policy executed in that report.
// Per-policy execution proof would require ingest-path metadata.
func (ds *Datastore) CheckPfPolicyCompliance(ctx context.Context, hostID, policyID uint) (fleet.PfObservation, error) {
	const stmt = `
  SELECT h.policy_updated_at, pm.passes
  FROM hosts h
  LEFT JOIN policy_membership pm ON pm.host_id = h.id AND pm.policy_id = ?
  WHERE h.id = ?`
	var (
		reportedAt time.Time
		passes     sql.NullBool
	)
	if err := ds.reader(ctx).QueryRowxContext(ctx, stmt, policyID, hostID).Scan(&reportedAt, &passes); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// Host is gone (ledger cleanup follows via hostRefs). Pause, never clean.
			return fleet.PfObservation{Outcome: fleet.PfOutcomeUnknown}, nil
		}
		return fleet.PfObservation{}, ctxerr.Wrap(ctx, err, "check pf policy compliance")
	}
	obs := fleet.PfObservation{
		ObservationID: fmt.Sprintf("policy-report-%d", reportedAt.Unix()),
		ObservedAt:    reportedAt,
	}
	switch {
	case !passes.Valid:
		obs.Outcome = fleet.PfOutcomeUnknown // no result recorded yet
	case passes.Bool:
		obs.Outcome = fleet.PfOutcomeClean
	default:
		obs.Outcome = fleet.PfOutcomeFailing
	}
	return obs, nil
}

// CheckPfCVECompliance observes one CVE finding. A clean observation requires
// one complete post-remediation cycle:
//
//  1. A host software inventory received after the finding fired
//     (host_updates.software_updated_at > firedAt).
//  2. A completed vulnerability-processing run that consumed that inventory
//     (latest completed cron_stats run for "vulnerabilities" ends after the
//     inventory timestamp).
//  3. The CVE absent across software and operating-system vulnerability
//     sources for the host.
//
// Anything missing or stale returns Unknown. The absent-row check alone is
// never sufficient: software ingestion and vulnerability matching are
// separate stages, so a CVE can be transiently absent between them.
func (ds *Datastore) CheckPfCVECompliance(ctx context.Context, hostID uint, cve string, firedAt time.Time) (fleet.PfObservation, error) {
	var invAt sql.NullTime
	err := ds.reader(ctx).QueryRowxContext(ctx,
		`SELECT software_updated_at FROM host_updates WHERE host_id = ?`, hostID).Scan(&invAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fleet.PfObservation{Outcome: fleet.PfOutcomeUnknown}, nil
		}
		return fleet.PfObservation{}, ctxerr.Wrap(ctx, err, "check pf cve inventory")
	}
	if !invAt.Valid || !invAt.Time.After(firedAt) {
		return fleet.PfObservation{Outcome: fleet.PfOutcomeUnknown}, nil
	}

	var runEnd sql.NullTime
	err = ds.reader(ctx).QueryRowxContext(ctx, `
  SELECT updated_at FROM cron_stats
  WHERE name = ? AND status = 'completed'
  ORDER BY updated_at DESC LIMIT 1`, string(fleet.CronVulnerabilities)).Scan(&runEnd)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fleet.PfObservation{Outcome: fleet.PfOutcomeUnknown}, nil
		}
		return fleet.PfObservation{}, ctxerr.Wrap(ctx, err, "check pf cve processing run")
	}
	if !runEnd.Valid || !runEnd.Time.After(invAt.Time) {
		// Inventory arrived but no processing run has consumed it yet.
		return fleet.PfObservation{Outcome: fleet.PfOutcomeUnknown}, nil
	}

	present, err := ds.pfCVEPresent(ctx, hostID, cve)
	if err != nil {
		return fleet.PfObservation{}, err
	}
	obs := fleet.PfObservation{
		ObservationID: fmt.Sprintf("inv-%d/vuln-%d", invAt.Time.Unix(), runEnd.Time.Unix()),
		ObservedAt:    runEnd.Time,
	}
	if present {
		obs.Outcome = fleet.PfOutcomeFailing
	} else {
		obs.Outcome = fleet.PfOutcomeClean
	}
	return obs, nil
}

func (ds *Datastore) pfCVEPresent(ctx context.Context, hostID uint, cve string) (bool, error) {
	queries := []string{
		`SELECT 1 FROM host_software hs
		  JOIN software_cve sc ON sc.software_id = hs.software_id
		  WHERE hs.host_id = ? AND sc.cve = ? LIMIT 1`,
		`SELECT 1 FROM host_operating_system hos
		  JOIN operating_system_vulnerabilities osv ON osv.operating_system_id = hos.os_id
		  WHERE hos.host_id = ? AND osv.cve = ? LIMIT 1`,
		`SELECT 1 FROM host_operating_system hos
		  JOIN operating_systems os ON os.id = hos.os_id
		  JOIN operating_system_version_vulnerabilities osvv ON osvv.os_version_id = os.os_version_id
		  WHERE hos.host_id = ? AND osvv.cve = ? LIMIT 1`,
	}
	for _, q := range queries {
		var one int
		err := ds.reader(ctx).QueryRowxContext(ctx, q, hostID, cve).Scan(&one)
		switch {
		case err == nil:
			return true, nil
		case errors.Is(err, sql.ErrNoRows):
			continue
		default:
			return false, ctxerr.Wrap(ctx, err, "check pf cve presence")
		}
	}
	return false, nil
}

// MarkPfGroupClearedFromClearing atomically transitions clearing rows to
// cleared. Only rows already in clearing move, so a violation that re-fired
// mid-close (state pending_discovery) survives. It returns true when every
// expected row moved; a mismatch means a new fire invalidated the close and
// the caller must abort.
func (ds *Datastore) MarkPfGroupClearedFromClearing(ctx context.Context, hostMAC, pfEventType string, expected int64) (bool, error) {
	const stmt = `
  UPDATE pf_revocation_ledger
  SET state = 'cleared', next_retry_at = NULL, last_error = NULL
  WHERE host_mac = ? AND pf_event_type = ? AND state = 'clearing'`
	res, err := ds.writer(ctx).ExecContext(ctx, stmt, hostMAC, pfEventType)
	if err != nil {
		return false, ctxerr.Wrap(ctx, err, "mark pf group cleared")
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, ctxerr.Wrap(ctx, err, "mark pf group cleared rows")
	}
	return affected == expected, nil
}
