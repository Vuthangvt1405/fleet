// Package packetfence reconciles Fleet policy/CVE findings with PacketFence
// security events: it validates recovery and requests event closure through
// PacketFence's existing REST API. Decisions are made per (MAC, PacketFence
// event type) group, never per individual finding, because PacketFence
// closes all non-closed events for a MAC and event type at once.
package packetfence

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/service/externalsvc"
)

// Defaults for the v1 revocation specification.
const (
	DefaultPolicyCleanChecks = 2
	DefaultCVECleanChecks    = 1
	DefaultPollLimit         = 100
	DefaultRetryBackoff      = 5 * time.Minute
)

// Config is the Fleet-side revocation configuration. These are proposed Fleet
// settings, not PacketFence settings. Default event IDs below must only be
// used after verifying the PacketFence rule configuration dedicates them
// exclusively to Fleet.
type Config struct {
	// Enabled gates the cron schedule. The worker does nothing unless the
	// PacketFence connection is configured.
	Enabled bool
	// BaseURL, Username, Password identify the PacketFence Unified API with
	// SECURITY_EVENTS_READ + NODES_UPDATE permissions (separate least-privilege
	// account, not the FLEETDM_EVENTS_READ webhook receiver).
	BaseURL  string
	Username string
	Password string
	// CAFile optionally loads additional root CAs for lab environments.
	CAFile string
	// ManagedEventTypes is the explicit allowlist of PacketFence event types
	// Fleet may clear. Types outside it are never automatically closed.
	ManagedEventTypes []string
	// RequireExclusiveOwnership refuses automatic close whenever exclusive
	// Fleet ownership cannot be established. V1 default true (fail closed).
	RequireExclusiveOwnership bool
	// PolicyChecksRequired is the number of distinct fresh policy evaluations
	// required (default 2). CVEChecksRequired is the number of complete
	// post-remediation processing cycles required (default 1).
	PolicyChecksRequired int
	CVEChecksRequired    int
	// PollLimit bounds findings per run; PollLimit groups them by event group.
	PollLimit int
	// RetryBackoff delays the next attempt after a pause or failure.
	RetryBackoff time.Duration
	// DryRun logs close decisions without calling PacketFence. For validation
	// and rollout before enabling automatic revocation.
	DryRun bool
	// ReevaluateAfterClose preserves the recovery.py sequence (close + explicit
	// reevaluate_access). PacketFence's close controller already reevaluates,
	// so this defaults off to avoid a redundant second call.
	ReevaluateAfterClose bool
}

// ConfigFromEnv loads v1 revocation settings from the environment. The cron
// stays disabled unless endpoint and credentials are all present.
func ConfigFromEnv() Config {
	managed := strings.Split(os.Getenv("FLEET_PACKETFENCE_MANAGED_EVENT_TYPES"), ",")
	var types []string
	for _, t := range managed {
		if t = strings.TrimSpace(t); t != "" {
			types = append(types, t)
		}
	}
	if len(types) == 0 {
		types = []string{"3500001", "3500002", "3500003"}
	}
	policyChecks := DefaultPolicyCleanChecks
	if v, err := strconv.Atoi(os.Getenv("FLEET_PACKETFENCE_POLICY_CHECKS")); err == nil && v > 0 {
		policyChecks = v
	}
	cveChecks := DefaultCVECleanChecks
	if v, err := strconv.Atoi(os.Getenv("FLEET_PACKETFENCE_CVE_CHECKS")); err == nil && v > 0 {
		cveChecks = v
	}
	base, user, pass := os.Getenv("FLEET_PACKETFENCE_BASE_URL"), os.Getenv("FLEET_PACKETFENCE_USERNAME"), os.Getenv("FLEET_PACKETFENCE_PASSWORD")
	return Config{
		Enabled:                   base != "" && user != "" && pass != "",
		BaseURL:                   base,
		Username:                  user,
		Password:                  pass,
		CAFile:                    os.Getenv("FLEET_PACKETFENCE_CA_FILE"),
		ManagedEventTypes:         types,
		RequireExclusiveOwnership: os.Getenv("FLEET_PACKETFENCE_REQUIRE_EXCLUSIVE_OWNERSHIP") != "false",
		PolicyChecksRequired:      policyChecks,
		CVEChecksRequired:         cveChecks,
		PollLimit:                 DefaultPollLimit,
		RetryBackoff:              DefaultRetryBackoff,
		DryRun:                    os.Getenv("FLEET_PACKETFENCE_DRY_RUN") == "true",
	}
}

// LedgerStore is the narrow persistence contract the reconciler needs. It is
// satisfied by *mysql.Datastore without extending fleet.Datastore.
type LedgerStore interface {
	ListPfRevocationDue(ctx context.Context, now time.Time, limit int) ([]*fleet.PfRevocationFinding, error)
	ListPfRevocationGroup(ctx context.Context, hostMAC, pfEventType string) ([]*fleet.PfRevocationFinding, error)
	UpdatePfRevocationFinding(ctx context.Context, f *fleet.PfRevocationFinding) error
	MarkPfGroupClearedFromClearing(ctx context.Context, hostMAC, pfEventType string, expected int64) (bool, error)
}

// PolicyChecker observes policy findings; CVEChecker observes CVE findings.
type PolicyChecker interface {
	CheckPfPolicyCompliance(ctx context.Context, hostID, policyID uint) (fleet.PfObservation, error)
}

// CVEChecker observes CVE findings.
type CVEChecker interface {
	CheckPfCVECompliance(ctx context.Context, hostID uint, cve string, firedAt time.Time) (fleet.PfObservation, error)
}

// PFConnector is the PacketFence REST surface the reconciler needs. It is
// satisfied by *externalsvc.PacketFence.
type PFConnector interface {
	Login(ctx context.Context) (string, error)
	FindMatchingEvent(ctx context.Context, token, mac, eventType string) (eventID string, isOpen bool, err error)
	CloseEvent(ctx context.Context, token, mac, instanceID string) error
	VerifyClosed(ctx context.Context, token, mac, eventType string) (bool, error)
	ReevaluateAccess(ctx context.Context, token, mac string) error
}

// Compile-time assertions that the «proven» implementations satisfy the
// narrow contracts.
var (
	_ PFConnector = (*externalsvc.PacketFence)(nil)
)

// Reconciler validates recovery per PacketFence event group and requests
// closure. It assumes a single runner (Fleet cron machinery guarantees one
// instance per schedule); group state predicates keep reruns safe.
type Reconciler struct {
	cfg      Config
	managed  map[string]bool
	store    LedgerStore
	policies PolicyChecker
	cves     CVEChecker
	pf       PFConnector
	now      func() time.Time
	logger   *slog.Logger
}

// NewReconciler builds a reconciler. Managed types are allowlisted as given;
// an empty allowlist blocks everything (fail closed).
func NewReconciler(cfg Config, store LedgerStore, policies PolicyChecker, cves CVEChecker, pf PFConnector, logger *slog.Logger) *Reconciler {
	if cfg.PolicyChecksRequired <= 0 {
		cfg.PolicyChecksRequired = DefaultPolicyCleanChecks
	}
	if cfg.CVEChecksRequired <= 0 {
		cfg.CVEChecksRequired = DefaultCVECleanChecks
	}
	if cfg.PollLimit <= 0 {
		cfg.PollLimit = DefaultPollLimit
	}
	if cfg.RetryBackoff <= 0 {
		cfg.RetryBackoff = DefaultRetryBackoff
	}
	managed := make(map[string]bool, len(cfg.ManagedEventTypes))
	for _, t := range cfg.ManagedEventTypes {
		managed[strings.TrimSpace(t)] = true
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Reconciler{cfg: cfg, managed: managed, store: store, policies: policies, cves: cves, pf: pf, now: time.Now, logger: logger}
}

// RunOnce reconciles every due group. Per-group errors are collected and
// returned joined; one group's failure never blocks the others.
func (r *Reconciler) RunOnce(ctx context.Context) error {
	due, err := r.store.ListPfRevocationDue(ctx, r.now(), r.cfg.PollLimit)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "list due pf revocation findings")
	}
	groups := make(map[fleet.PfGroupKey]bool)
	var order []fleet.PfGroupKey
	for _, f := range due {
		k := f.GroupKey()
		if !groups[k] {
			groups[k] = true
			order = append(order, k)
		}
	}
	if len(order) == 0 {
		return nil
	}
	token, err := r.pf.Login(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "packetfence login")
	}
	var errs []error
	for _, k := range order {
		if err := r.reconcileGroup(ctx, token, k.HostMAC, k.PfEventType); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ReconcileGroup reconciles one event group, logging in first. It is exported
// for ad-hoc/manual triggers; the cron path uses RunOnce.
func (r *Reconciler) ReconcileGroup(ctx context.Context, hostMAC, pfEventType string) error {
	token, err := r.pf.Login(ctx)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "packetfence login")
	}
	return r.reconcileGroup(ctx, token, hostMAC, pfEventType)
}

func (r *Reconciler) reconcileGroup(ctx context.Context, token, hostMAC, pfEventType string) error {
	findings, err := r.store.ListPfRevocationGroup(ctx, hostMAC, pfEventType)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "list pf revocation group")
	}
	if len(findings) == 0 {
		// Never assume closed when nothing is recorded.
		return nil
	}

	// Ownership gate: fail closed for shared or foreign types.
	if !r.managed[pfEventType] {
		return r.blockGroup(ctx, findings, fmt.Sprintf("packetfence event type %s is not Fleet-managed", pfEventType))
	}
	// A group carrying an ownership block stays blocked until an explicit
	// manual override, even if the type has since become managed.
	for _, f := range findings {
		if f.State == fleet.PfStateOwnershipBlocked {
			return r.blockGroup(ctx, findings, "group contains an ownership-blocked finding")
		}
	}

	// Observe compliance using fresh Fleet data; every finding in the group
	// must resolve before the shared event may close.
	allClean := true
	for _, f := range findings {
		clean, err := r.observeFinding(ctx, f)
		if err != nil {
			return err
		}
		if !clean {
			allClean = false
		}
	}
	if !allClean {
		return nil
	}

	// Discover the PacketFence event we own. A 202 webhook accept is not
	// evidence the event exists, so an undiscoverable event pauses recovery.
	instanceID, isOpen, err := r.pf.FindMatchingEvent(ctx, token, hostMAC, pfEventType)
	if err != nil {
		if errors.Is(err, externalsvc.ErrPacketFenceEventNotFound) {
			r.logger.InfoContext(ctx, "packetfence event not yet discovered; pausing",
				"mac", hostMAC, "event_type", pfEventType)
			r.scheduleGroupRetry(ctx, findings, "packetfence event not discovered")
			return nil
		}
		return r.retryGroupErr(ctx, findings, err)
	}

	// Record discovery: persist the real instance ID and promote pending rows.
	for _, f := range findings {
		changed := false
		if f.PfEventID == nil || *f.PfEventID != instanceID {
			f.PfEventID = &instanceID
			changed = true
		}
		if f.State == fleet.PfStatePendingDiscovery {
			f.State = fleet.PfStateActive
			changed = true
		}
		if changed {
			if err := r.store.UpdatePfRevocationFinding(ctx, f); err != nil {
				return ctxerr.Wrap(ctx, err, "record pf event discovery")
			}
		}
	}

	if r.cfg.DryRun {
		r.logger.InfoContext(ctx, "packetfence dry-run: would close event",
			"mac", hostMAC, "event_type", pfEventType, "instance", instanceID, "findings", len(findings))
		return nil
	}

	// Mark clearing before the close request so a re-fire (which resets rows
	// to pending_discovery via upsert) is detectable after verification.
	for _, f := range findings {
		f.State = fleet.PfStateClearing
		f.NextRetryAt = nil
		f.LastError = nil
		if err := r.store.UpdatePfRevocationFinding(ctx, f); err != nil {
			return ctxerr.Wrap(ctx, err, "mark pf group clearing")
		}
	}
	decisionTime := r.now()

	if isOpen {
		if err := r.pf.CloseEvent(ctx, token, hostMAC, instanceID); err != nil {
			return r.retryGroupErr(ctx, findings, fmt.Errorf("close packetfence event: %w", err))
		}
		if r.cfg.ReevaluateAfterClose {
			if err := r.pf.ReevaluateAccess(ctx, token, hostMAC); err != nil {
				return r.retryGroupErr(ctx, findings, fmt.Errorf("reevaluate packetfence access: %w", err))
			}
		}
	}

	// Never trust HTTP success alone: confirm PacketFence state before
	// reporting cleared.
	closed, err := r.pf.VerifyClosed(ctx, token, hostMAC, pfEventType)
	if err != nil {
		return r.retryGroupErr(ctx, findings, err)
	}
	if !closed {
		return r.retryGroupErr(ctx, findings, errors.New("packetfence event still open after close"))
	}

	// Quiescence re-check: a violation that fired after the clean decision
	// invalidates the close. Fresh rows (pending_discovery) or newer fired_at
	// abort the transition; the atomic mark below is the final guard.
	fresh, err := r.store.ListPfRevocationGroup(ctx, hostMAC, pfEventType)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "re-list pf revocation group")
	}
	for _, f := range fresh {
		if f.State != fleet.PfStateClearing || f.FiredAt.After(decisionTime) {
			r.logger.InfoContext(ctx, "new violation invalidated pending close",
				"mac", hostMAC, "event_type", pfEventType)
			return nil
		}
	}

	ok, err := r.store.MarkPfGroupClearedFromClearing(ctx, hostMAC, pfEventType, int64(len(findings)))
	if err != nil {
		return ctxerr.Wrap(ctx, err, "mark pf group cleared")
	}
	if !ok {
		r.logger.InfoContext(ctx, "close race detected; leaving group for next run",
			"mac", hostMAC, "event_type", pfEventType)
		return nil
	}
	r.logger.InfoContext(ctx, "packetfence event cleared",
		"mac", hostMAC, "event_type", pfEventType, "instance", instanceID)
	return nil
}

// observeFinding checks one finding and persists clean progress. It reports
// whether the finding has met its required clean threshold.
func (r *Reconciler) observeFinding(ctx context.Context, f *fleet.PfRevocationFinding) (bool, error) {
	required, obs, err := r.check(ctx, f)
	if err != nil {
		// Checker/DB failure: back off, but surface it so the cron run
		// records the error instead of silently pausing.
		if uerr := r.pauseOne(ctx, f, err.Error()); uerr != nil {
			return false, errors.Join(err, uerr)
		}
		return false, err
	}
	switch obs.Outcome {
	case fleet.PfOutcomeUnknown:
		// Missing or stale evidence pauses without counting.
		return false, r.pauseOne(ctx, f, "awaiting fresh evidence")
	case fleet.PfOutcomeFailing:
		if f.CleanChecks != 0 || f.LastCountedObservationID != nil {
			f.CleanChecks = 0
			f.LastCountedObservationID = nil
			f.LastObservationAt = &obs.ObservedAt
			f.NextRetryAt = nil
			f.LastError = nil
			if err := r.store.UpdatePfRevocationFinding(ctx, f); err != nil {
				return false, ctxerr.Wrap(ctx, err, "reset pf clean checks")
			}
		}
		return false, nil
	case fleet.PfOutcomeClean:
		// Freshness is a property of the security observation, not the poll:
		// the same observation counted twice is still one check, and evidence
		// predating the fire proves nothing about recovery.
		if obs.ObservationID == stringOrEmpty(f.LastCountedObservationID) {
			if uerr := r.pauseOne(ctx, f, "awaiting new observation"); uerr != nil {
				return false, uerr
			}
			return f.CleanChecks >= required, nil
		}
		if !obs.ObservedAt.After(f.FiredAt) {
			return false, r.pauseOne(ctx, f, "observation predates violation")
		}
		f.CleanChecks++
		f.LastCountedObservationID = &obs.ObservationID
		f.LastObservationAt = &obs.ObservedAt
		f.NextRetryAt = nil
		f.LastError = nil
		if err := r.store.UpdatePfRevocationFinding(ctx, f); err != nil {
			return false, ctxerr.Wrap(ctx, err, "record pf clean check")
		}
		if f.CleanChecks < required {
			return false, nil
		}
		return true, nil
	default:
		return false, r.pauseOne(ctx, f, "unknown observation outcome")
	}
}

func (r *Reconciler) check(ctx context.Context, f *fleet.PfRevocationFinding) (int, fleet.PfObservation, error) {
	switch f.TriggerType {
	case fleet.PfTriggerPolicy:
		if f.PolicyID == nil {
			return 0, fleet.PfObservation{}, fmt.Errorf("policy finding %d has no policy_id", f.ID)
		}
		obs, err := r.policies.CheckPfPolicyCompliance(ctx, f.HostID, *f.PolicyID)
		return r.cfg.PolicyChecksRequired, obs, err
	case fleet.PfTriggerCVE:
		if f.CVE == nil {
			return 0, fleet.PfObservation{}, fmt.Errorf("cve finding %d has no cve", f.ID)
		}
		obs, err := r.cves.CheckPfCVECompliance(ctx, f.HostID, *f.CVE, f.FiredAt)
		return r.cfg.CVEChecksRequired, obs, err
	default:
		return 0, fleet.PfObservation{}, fmt.Errorf("finding %d has unknown trigger type %q", f.ID, f.TriggerType)
	}
}

func (r *Reconciler) blockGroup(ctx context.Context, findings []*fleet.PfRevocationFinding, reason string) error {
	for _, f := range findings {
		if f.State == fleet.PfStateOwnershipBlocked {
			continue
		}
		f.State = fleet.PfStateOwnershipBlocked
		f.OwnershipBlockReason = &reason
		f.NextRetryAt = nil
		f.LastError = nil
		if err := r.store.UpdatePfRevocationFinding(ctx, f); err != nil {
			return ctxerr.Wrap(ctx, err, "block pf group")
		}
	}
	r.logger.InfoContext(ctx, "refused automatic packetfence close", "reason", reason, "findings", len(findings))
	return nil
}

func (r *Reconciler) retryGroupErr(ctx context.Context, findings []*fleet.PfRevocationFinding, err error) error {
	for _, f := range findings {
		r.scheduleOneRetry(ctx, f, err.Error())
		if uerr := r.persistRetry(ctx, f); uerr != nil {
			return errors.Join(err, uerr)
		}
	}
	return err
}

// scheduleGroupRetry backs off every row in the group for an expected pause
// (undiscovered event, stale evidence). It never reports an error.
func (r *Reconciler) scheduleGroupRetry(ctx context.Context, findings []*fleet.PfRevocationFinding, msg string) {
	for _, f := range findings {
		r.scheduleOneRetry(ctx, f, msg)
		_ = r.persistRetry(ctx, f)
	}
}

// scheduleOneRetry stamps backoff metadata on a finding. A retryable failure
// during clearing returns the row to active so the next run re-validates
// before attempting another close.
func (r *Reconciler) scheduleOneRetry(_ context.Context, f *fleet.PfRevocationFinding, msg string) {
	next := r.now().Add(r.cfg.RetryBackoff)
	f.NextRetryAt = &next
	f.LastError = &msg
	if f.State == fleet.PfStateClearing {
		f.State = fleet.PfStateActive
	}
}

// pauseOne backs off one finding for an expected pause (stale evidence,
// undiscovered event). It returns only persistence failures.
func (r *Reconciler) pauseOne(ctx context.Context, f *fleet.PfRevocationFinding, msg string) error {
	r.scheduleOneRetry(ctx, f, msg)
	return r.persistRetry(ctx, f)
}

func (r *Reconciler) persistRetry(ctx context.Context, f *fleet.PfRevocationFinding) error {
	return ctxerr.Wrap(ctx, r.store.UpdatePfRevocationFinding(ctx, f), "schedule pf retry")
}

func stringOrEmpty(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
