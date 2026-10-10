package packetfence

import (
	"context"
	"fmt"
	"log/slog"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/service/externalsvc"
	"github.com/stretchr/testify/require"
)

func uintPtr(v uint) *uint           { return &v }
func strPtr(v string) *string        { return &v }
func timePtr(v time.Time) *time.Time { return &v }

var testTime = time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)

func policyFinding(id, hostID, policyID uint, firedAt time.Time) *fleet.PfRevocationFinding {
	return &fleet.PfRevocationFinding{
		ID: id, HostID: hostID, HostMAC: "aa:bb:cc:dd:ee:ff",
		TriggerType: fleet.PfTriggerPolicy, PolicyID: uintPtr(policyID),
		PfEventType: "3500001", FiredAt: firedAt, State: fleet.PfStateActive,
	}
}

func cveFinding(id, hostID uint, cve string, firedAt time.Time) *fleet.PfRevocationFinding {
	return &fleet.PfRevocationFinding{
		ID: id, HostID: hostID, HostMAC: "aa:bb:cc:dd:ee:ff",
		TriggerType: fleet.PfTriggerCVE, CVE: strPtr(cve),
		PfEventType: "3500002", FiredAt: firedAt, State: fleet.PfStateActive,
	}
}

// fakeStore is an in-memory LedgerStore.
type fakeStore struct {
	rows         map[uint]*fleet.PfRevocationFinding
	onListGroup  func(call int)
	listCalls    int
	clearedCalls int
}

func (s *fakeStore) ListPfRevocationDue(_ context.Context, now time.Time, _ int) ([]*fleet.PfRevocationFinding, error) {
	var out []*fleet.PfRevocationFinding
	for _, f := range s.rows {
		if f.State == fleet.PfStateCleared || f.State == fleet.PfStateOwnershipBlocked {
			continue
		}
		if f.NextRetryAt == nil || !f.NextRetryAt.After(now) {
			out = append(out, f)
		}
	}
	return out, nil
}

func (s *fakeStore) ListPfRevocationGroup(_ context.Context, mac, typ string) ([]*fleet.PfRevocationFinding, error) {
	s.listCalls++
	// The hook runs before the select so tests can simulate a concurrent
	// fire committing between the worker's own queries, mirroring a real
	// SELECT that would observe already-committed rows.
	if s.onListGroup != nil {
		s.onListGroup(s.listCalls)
	}
	var out []*fleet.PfRevocationFinding
	for _, f := range s.rows {
		if f.HostMAC == mac && f.PfEventType == typ && f.State != fleet.PfStateCleared {
			out = append(out, f)
		}
	}
	return out, nil
}

func (s *fakeStore) UpdatePfRevocationFinding(_ context.Context, f *fleet.PfRevocationFinding) error {
	cpy := *f
	s.rows[f.ID] = &cpy
	return nil
}

func (s *fakeStore) MarkPfGroupClearedFromClearing(_ context.Context, mac, typ string, expected int64) (bool, error) {
	s.clearedCalls++
	var affected int64
	for _, f := range s.rows {
		if f.HostMAC == mac && f.PfEventType == typ && f.State == fleet.PfStateClearing {
			f.State = fleet.PfStateCleared
			affected++
		}
	}
	return affected == expected, nil
}

type fakePolicies struct {
	obs map[string][]fleet.PfObservation
	err error
}

func (p *fakePolicies) CheckPfPolicyCompliance(_ context.Context, hostID, policyID uint) (fleet.PfObservation, error) {
	if p.err != nil {
		return fleet.PfObservation{}, p.err
	}
	key := policyKey(hostID, policyID)
	if q := p.obs[key]; len(q) > 0 {
		o := q[0]
		p.obs[key] = q[1:]
		return o, nil
	}
	return fleet.PfObservation{Outcome: fleet.PfOutcomeUnknown}, nil
}

func policyKey(hostID, policyID uint) string {
	return fmt.Sprintf("%d/%d", hostID, policyID)
}

type fakeCVEs struct {
	obs map[string][]fleet.PfObservation
}

func (c *fakeCVEs) CheckPfCVECompliance(_ context.Context, hostID uint, cve string, _ time.Time) (fleet.PfObservation, error) {
	q := c.obs[cve]
	if len(q) > 0 {
		o := q[0]
		c.obs[cve] = q[1:]
		return o, nil
	}
	return fleet.PfObservation{Outcome: fleet.PfOutcomeUnknown}, nil
}

type fakePF struct {
	eventID     string
	isOpen      bool
	findErr     error
	verify      []bool
	closeErr    error
	closes      int
	reevaluates int
	logins      int
	verifiedArg string
}

func (p *fakePF) Login(_ context.Context) (string, error) { p.logins++; return "tok", nil }

func (p *fakePF) FindMatchingEvent(_ context.Context, _, _, _ string) (string, bool, error) {
	if p.findErr != nil {
		return "", false, p.findErr
	}
	return p.eventID, p.isOpen, nil
}

func (p *fakePF) CloseEvent(_ context.Context, _, _, _ string) error {
	p.closes++
	return p.closeErr
}

func (p *fakePF) VerifyClosed(_ context.Context, _, _, _ string) (bool, error) {
	if len(p.verify) > 0 {
		v := p.verify[0]
		p.verify = p.verify[1:]
		return v, nil
	}
	return true, nil
}

func (p *fakePF) ReevaluateAccess(_ context.Context, _, _ string) error { p.reevaluates++; return nil }

func testConfig() Config {
	return Config{
		Enabled:                   true,
		ManagedEventTypes:         []string{"3500001", "3500002", "3500003"},
		RequireExclusiveOwnership: true,
		PolicyChecksRequired:      2,
		CVEChecksRequired:         1,
		PollLimit:                 100,
		RetryBackoff:              5 * time.Minute,
	}
}

func newTestReconciler(store *fakeStore, pol *fakePolicies, cves *fakeCVEs, pf *fakePF) *Reconciler {
	r := NewReconciler(testConfig(), store, pol, cves, pf, slog.Default())
	r.now = func() time.Time { return testTime }
	return r
}

func cleanPolicyObs(id string, at time.Time) fleet.PfObservation {
	return fleet.PfObservation{Outcome: fleet.PfOutcomeClean, ObservationID: id, ObservedAt: at}
}

// Two polls of one policy pass count once; no close happens.
func TestReconcileDuplicatePollIsOneObservation(t *testing.T) {
	fired := testTime.Add(-time.Hour)
	store := &fakeStore{rows: map[uint]*fleet.PfRevocationFinding{1: policyFinding(1, 42, 7, fired)}}
	obsAt := testTime.Add(-30 * time.Minute)
	pol := &fakePolicies{obs: map[string][]fleet.PfObservation{
		policyKey(42, 7): {cleanPolicyObs("report-1", obsAt), cleanPolicyObs("report-1", obsAt)},
	}}
	pf := &fakePF{eventID: "123", isOpen: true}
	r := newTestReconciler(store, pol, &fakeCVEs{}, pf)

	require.NoError(t, r.ReconcileGroup(context.Background(), "aa:bb:cc:dd:ee:ff", "3500001"))
	require.NoError(t, r.ReconcileGroup(context.Background(), "aa:bb:cc:dd:ee:ff", "3500001"))

	f := store.rows[1]
	require.Equal(t, 1, f.CleanChecks)
	require.Equal(t, "report-1", *f.LastCountedObservationID)
	require.Equal(t, 0, pf.closes, "must not close after a single distinct observation")
	require.NotEqual(t, fleet.PfStateCleared, f.State)
}

// Two distinct passing evaluations permit recovery and close.
func TestReconcileTwoDistinctPolicyEvalsClose(t *testing.T) {
	fired := testTime.Add(-2 * time.Hour)
	store := &fakeStore{rows: map[uint]*fleet.PfRevocationFinding{1: policyFinding(1, 42, 7, fired)}}
	pol := &fakePolicies{obs: map[string][]fleet.PfObservation{
		policyKey(42, 7): {
			cleanPolicyObs("report-1", testTime.Add(-90*time.Minute)),
			cleanPolicyObs("report-2", testTime.Add(-10*time.Minute)),
		},
	}}
	pf := &fakePF{eventID: "123", isOpen: true, verify: []bool{true}}
	r := newTestReconciler(store, pol, &fakeCVEs{}, pf)

	require.NoError(t, r.ReconcileGroup(context.Background(), "aa:bb:cc:dd:ee:ff", "3500001"))
	require.Equal(t, 0, pf.closes, "first distinct observation is 1/2")
	require.Equal(t, 1, store.rows[1].CleanChecks)

	// Retry is scheduled in the future; clear it to simulate the next due run.
	store.rows[1].NextRetryAt = nil
	require.NoError(t, r.ReconcileGroup(context.Background(), "aa:bb:cc:dd:ee:ff", "3500001"))
	require.Equal(t, 1, pf.closes)
	require.Equal(t, fleet.PfStateCleared, store.rows[1].State)
	require.Equal(t, "123", *store.rows[1].PfEventID)
}

// One complete CVE cycle permits recovery when the CVE is absent.
func TestReconcileCVECycleCloses(t *testing.T) {
	fired := testTime.Add(-3 * time.Hour)
	store := &fakeStore{rows: map[uint]*fleet.PfRevocationFinding{1: cveFinding(1, 42, "CVE-2024-1234", fired)}}
	cves := &fakeCVEs{obs: map[string][]fleet.PfObservation{
		"CVE-2024-1234": {{Outcome: fleet.PfOutcomeClean, ObservationID: "inv-1/vuln-2", ObservedAt: testTime.Add(-time.Hour)}},
	}}
	pf := &fakePF{eventID: "999", isOpen: true, verify: []bool{true}}
	r := newTestReconciler(store, &fakePolicies{}, cves, pf)

	require.NoError(t, r.ReconcileGroup(context.Background(), "aa:bb:cc:dd:ee:ff", "3500002"))
	require.Equal(t, 1, pf.closes)
	require.Equal(t, fleet.PfStateCleared, store.rows[1].State)
}

// Stale or missing inventory never permits recovery.
func TestReconcileStaleInventoryPauses(t *testing.T) {
	fired := testTime.Add(-3 * time.Hour)
	store := &fakeStore{rows: map[uint]*fleet.PfRevocationFinding{1: cveFinding(1, 42, "CVE-2024-1234", fired)}}
	cves := &fakeCVEs{} // no observations: checker reports unknown
	pf := &fakePF{eventID: "999", isOpen: true}
	r := newTestReconciler(store, &fakePolicies{}, cves, pf)

	require.NoError(t, r.ReconcileGroup(context.Background(), "aa:bb:cc:dd:ee:ff", "3500002"))
	require.Equal(t, 0, pf.closes)
	require.NotEqual(t, fleet.PfStateCleared, store.rows[1].State)
	require.NotNil(t, store.rows[1].NextRetryAt, "pause schedules a retry")
}

// A foreign event type is never automatically closed.
func TestReconcileForeignTypeBlocked(t *testing.T) {
	fired := testTime.Add(-time.Hour)
	f := policyFinding(1, 42, 7, fired)
	f.PfEventType = "9999999"
	store := &fakeStore{rows: map[uint]*fleet.PfRevocationFinding{1: f}}
	pf := &fakePF{eventID: "1", isOpen: true}
	r := newTestReconciler(store, &fakePolicies{}, &fakeCVEs{}, pf)

	require.NoError(t, r.ReconcileGroup(context.Background(), "aa:bb:cc:dd:ee:ff", "9999999"))
	require.Equal(t, 0, pf.closes)
	require.Equal(t, fleet.PfStateOwnershipBlocked, store.rows[1].State)
	require.NotNil(t, store.rows[1].OwnershipBlockReason)
}

// One unresolved finding blocks a shared Fleet-owned type.
func TestReconcileSharedTypeBlockedByUnresolved(t *testing.T) {
	fired := testTime.Add(-2 * time.Hour)
	a := policyFinding(1, 42, 7, fired)
	b := policyFinding(2, 42, 8, fired)
	store := &fakeStore{rows: map[uint]*fleet.PfRevocationFinding{1: a, 2: b}}
	pol := &fakePolicies{obs: map[string][]fleet.PfObservation{
		policyKey(42, 7): {
			cleanPolicyObs("r1", testTime.Add(-90*time.Minute)),
			cleanPolicyObs("r2", testTime.Add(-10*time.Minute)),
		},
		policyKey(42, 8): {{Outcome: fleet.PfOutcomeFailing, ObservationID: "r1", ObservedAt: testTime.Add(-10 * time.Minute)}},
	}}
	pf := &fakePF{eventID: "123", isOpen: true}
	r := newTestReconciler(store, pol, &fakeCVEs{}, pf)
	r.cfg.PolicyChecksRequired = 1 // single check suffices so finding 1 is clean

	require.NoError(t, r.ReconcileGroup(context.Background(), "aa:bb:cc:dd:ee:ff", "3500001"))
	require.Equal(t, 0, pf.closes, "unresolved finding 2 must block the shared event")
	require.NotEqual(t, fleet.PfStateCleared, store.rows[1].State)
	require.NotEqual(t, fleet.PfStateCleared, store.rows[2].State)
}

// A newly fired violation invalidates a pending close decision.
func TestReconcileNewFireInvalidatesClose(t *testing.T) {
	fired := testTime.Add(-2 * time.Hour)
	store := &fakeStore{rows: map[uint]*fleet.PfRevocationFinding{1: policyFinding(1, 42, 7, fired)}}
	pol := &fakePolicies{obs: map[string][]fleet.PfObservation{
		policyKey(42, 7): {cleanPolicyObs("r1", testTime.Add(-time.Hour))},
	}}
	pf := &fakePF{eventID: "123", isOpen: true, verify: []bool{true}}
	r := newTestReconciler(store, pol, &fakeCVEs{}, pf)
	r.cfg.PolicyChecksRequired = 1

	// On the quiescence re-list (second ListGroup call), a new violation lands.
	store.onListGroup = func(call int) {
		if call == 2 {
			store.rows[2] = &fleet.PfRevocationFinding{
				ID: 2, HostID: 43, HostMAC: "aa:bb:cc:dd:ee:ff",
				TriggerType: fleet.PfTriggerPolicy, PolicyID: uintPtr(9),
				PfEventType: "3500001", FiredAt: testTime.Add(time.Minute),
				State: fleet.PfStatePendingDiscovery,
			}
		}
	}

	require.NoError(t, r.ReconcileGroup(context.Background(), "aa:bb:cc:dd:ee:ff", "3500001"))
	require.Equal(t, 0, store.clearedCalls, "close must not be marked cleared after a new fire")
	require.Equal(t, fleet.PfStatePendingDiscovery, store.rows[2].State)
}

// Close success is verified before marking cleared.
func TestReconcileVerifyRequired(t *testing.T) {
	fired := testTime.Add(-2 * time.Hour)
	store := &fakeStore{rows: map[uint]*fleet.PfRevocationFinding{1: policyFinding(1, 42, 7, fired)}}
	pol := &fakePolicies{obs: map[string][]fleet.PfObservation{
		policyKey(42, 7): {cleanPolicyObs("r1", testTime.Add(-time.Hour))},
	}}
	pf := &fakePF{eventID: "123", isOpen: true, verify: []bool{false}}
	r := newTestReconciler(store, pol, &fakeCVEs{}, pf)
	r.cfg.PolicyChecksRequired = 1

	err := r.ReconcileGroup(context.Background(), "aa:bb:cc:dd:ee:ff", "3500001")
	require.Error(t, err, "still-open after close must surface")
	require.Equal(t, 1, pf.closes)
	require.NotEqual(t, fleet.PfStateCleared, store.rows[1].State)
	require.Equal(t, 0, store.clearedCalls)
}

// Undiscovered events pause without assuming closure.
func TestReconcileUndiscoveredEventPauses(t *testing.T) {
	fired := testTime.Add(-2 * time.Hour)
	store := &fakeStore{rows: map[uint]*fleet.PfRevocationFinding{1: policyFinding(1, 42, 7, fired)}}
	pol := &fakePolicies{obs: map[string][]fleet.PfObservation{
		policyKey(42, 7): {cleanPolicyObs("r1", testTime.Add(-time.Hour))},
	}}
	pf := &fakePF{findErr: externalsvc.ErrPacketFenceEventNotFound}
	r := newTestReconciler(store, pol, &fakeCVEs{}, pf)
	r.cfg.PolicyChecksRequired = 1

	require.NoError(t, r.ReconcileGroup(context.Background(), "aa:bb:cc:dd:ee:ff", "3500001"))
	require.Equal(t, 0, pf.closes)
	require.NotEqual(t, fleet.PfStateCleared, store.rows[1].State)
}
