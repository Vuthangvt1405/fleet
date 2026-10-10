package fleet

import (
	"context"
	"time"
)

// PacketFence revocation ledger trigger types.
const (
	PfTriggerPolicy = "policy"
	PfTriggerCVE    = "cve"
)

// PacketFence revocation ledger states.
const (
	PfStatePendingDiscovery = "pending_discovery"
	PfStateActive           = "active"
	PfStateClearing         = "clearing"
	PfStateCleared          = "cleared"
	PfStateOwnershipBlocked = "ownership_blocked"
)

// PfRevocationFinding is one row of the pf_revocation_ledger table: a single
// Fleet finding (failed policy or CVE) that may trigger a PacketFence event.
//
// Rows are grouped by (HostMAC, PfEventType) at the application layer because
// PacketFence closes all non-closed rows for (mac, event type) at once. Close
// decisions must always be made for the entire group, never per row.
type PfRevocationFinding struct {
	ID                       uint       `db:"id" json:"id"`
	HostID                   uint       `db:"host_id" json:"host_id"`
	HostMAC                  string     `db:"host_mac" json:"host_mac"`
	TriggerType              string     `db:"trigger_type" json:"trigger_type"`
	PolicyID                 *uint      `db:"policy_id" json:"policy_id,omitempty"`
	CVE                      *string    `db:"cve" json:"cve,omitempty"`
	PfEventType              string     `db:"pf_event_type" json:"pf_event_type"`
	PfEventID                *string    `db:"pf_event_id" json:"pf_event_id,omitempty"`
	PfTaskKey                *string    `db:"pf_task_key" json:"pf_task_key,omitempty"`
	FiredAt                  time.Time  `db:"fired_at" json:"fired_at"`
	State                    string     `db:"state" json:"state"`
	CleanChecks              int        `db:"clean_checks" json:"clean_checks"`
	LastCountedObservationID *string    `db:"last_counted_observation_id" json:"last_counted_observation_id,omitempty"`
	LastObservationAt        *time.Time `db:"last_observation_at" json:"last_observation_at,omitempty"`
	NextRetryAt              *time.Time `db:"next_retry_at" json:"next_retry_at,omitempty"`
	LastError                *string    `db:"last_error" json:"last_error,omitempty"`
	OwnershipBlockReason     *string    `db:"ownership_block_reason" json:"ownership_block_reason,omitempty"`
	CreatedAt                time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt                time.Time  `db:"updated_at" json:"updated_at"`
}

// PfGroupKey identifies a PacketFence event group sharing one (mac, type).
type PfGroupKey struct {
	HostMAC     string
	PfEventType string
}

// GroupKey returns the event-group key for this finding.
func (f *PfRevocationFinding) GroupKey() PfGroupKey {
	return PfGroupKey{HostMAC: f.HostMAC, PfEventType: f.PfEventType}
}

// PfOutcome is the result of one fresh compliance observation for a finding.
type PfOutcome string

const (
	// PfOutcomeClean means fresh evidence shows the finding resolved.
	PfOutcomeClean PfOutcome = "clean"
	// PfOutcomeFailing means fresh evidence shows the finding still active.
	// Clean progress resets.
	PfOutcomeFailing PfOutcome = "failing"
	// PfOutcomeUnknown means evidence is missing or stale. The worker pauses
	// without counting for or against recovery. Unknown is never clean.
	PfOutcomeUnknown PfOutcome = "unknown"
)

// PfObservation is one compliance observation. ObservationID identifies the
// underlying security observation (e.g. a host policy report timestamp or an
// inventory/vulnerability-processing generation pair). Worker polls must never
// count as observations: a check only counts when ObservationID differs from
// the finding's LastCountedObservationID.
type PfObservation struct {
	Outcome       PfOutcome
	ObservationID string
	ObservedAt    time.Time
}

// PacketFenceStore is the persistence contract for the PacketFence revocation
// worker: ledger reads/writes plus policy and CVE compliance observations.
// It is part of Datastore so the caching, Redis and ETag decorators promote
// these methods to the fully wrapped datastore handed to cron.
type PacketFenceStore interface {
	UpsertPfRevocationFinding(ctx context.Context, f *PfRevocationFinding) (*PfRevocationFinding, error)
	ListPfRevocationDue(ctx context.Context, now time.Time, limit int) ([]*PfRevocationFinding, error)
	ListPfRevocationGroup(ctx context.Context, hostMAC, pfEventType string) ([]*PfRevocationFinding, error)
	UpdatePfRevocationFinding(ctx context.Context, f *PfRevocationFinding) error
	MarkPfGroupClearedFromClearing(ctx context.Context, hostMAC, pfEventType string, expected int64) (bool, error)
	CheckPfPolicyCompliance(ctx context.Context, hostID, policyID uint) (PfObservation, error)
	CheckPfCVECompliance(ctx context.Context, hostID uint, cve string, firedAt time.Time) (PfObservation, error)
}
