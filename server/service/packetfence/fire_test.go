package packetfence

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/stretchr/testify/require"
)

type fakeFireStore struct {
	hosts   map[uint]*fleet.Host
	upsert  []*fleet.PfRevocationFinding
	upErr   error
	hostErr error
}

func (s *fakeFireStore) Host(_ context.Context, id uint) (*fleet.Host, error) {
	if s.hostErr != nil {
		return nil, s.hostErr
	}
	h, ok := s.hosts[id]
	if !ok {
		return &fleet.Host{}, nil
	}
	return h, nil
}

func (s *fakeFireStore) UpsertPfRevocationFinding(_ context.Context, f *fleet.PfRevocationFinding) (*fleet.PfRevocationFinding, error) {
	if s.upErr != nil {
		return nil, s.upErr
	}
	cpy := *f
	s.upsert = append(s.upsert, &cpy)
	return &cpy, nil
}

func TestPfEventTypeForPolicyScopedToFirewall(t *testing.T) {
	typ, ok := PfEventTypeForPolicy(2)
	require.True(t, ok)
	require.Equal(t, "3500001", typ)

	_, ok = PfEventTypeForPolicy(1)
	require.False(t, ok)

	_, ok = PfEventTypeForPolicy(999)
	require.False(t, ok)
}

func TestNormalizeMAC(t *testing.T) {
	require.Equal(t, "50:54:46:00:5d:00", NormalizeMAC("50:54:46:00:5d:00"))
	require.Equal(t, "50:54:46:00:5d:00", NormalizeMAC(" 50-54-46-00-5D-00 "))
	require.Equal(t, "", NormalizeMAC("  "))
}

func TestRecordPolicyFireWritesLedger(t *testing.T) {
	ds := &fakeFireStore{hosts: map[uint]*fleet.Host{
		7: {PrimaryMac: "50:54:46:00:5D:00"},
	}}
	fired := time.Now()
	require.NoError(t, RecordPolicyFire(context.Background(), ds, 2, 7, fired))
	require.Len(t, ds.upsert, 1)
	f := ds.upsert[0]
	require.Equal(t, uint(7), f.HostID)
	require.Equal(t, "50:54:46:00:5d:00", f.HostMAC)
	require.Equal(t, fleet.PfTriggerPolicy, f.TriggerType)
	require.NotNil(t, f.PolicyID)
	require.Equal(t, uint(2), *f.PolicyID)
	require.Equal(t, "3500001", f.PfEventType)
	require.Equal(t, fleet.PfStatePendingDiscovery, f.State)
	require.True(t, f.FiredAt.Equal(fired))
}

func TestRecordPolicyFireIgnoresUnmappedPolicy(t *testing.T) {
	ds := &fakeFireStore{hosts: map[uint]*fleet.Host{
		7: {PrimaryMac: "50:54:46:00:5d:00"},
	}}
	require.NoError(t, RecordPolicyFire(context.Background(), ds, 99, 7, time.Now()))
	require.Empty(t, ds.upsert)
}

func TestRecordPolicyFireMissingMAC(t *testing.T) {
	ds := &fakeFireStore{hosts: map[uint]*fleet.Host{
		7: {PrimaryMac: "  "},
	}}
	require.Error(t, RecordPolicyFire(context.Background(), ds, 2, 7, time.Now()))
	require.Empty(t, ds.upsert)
}

func TestRecordPolicyFireBatchSkipsFailures(t *testing.T) {
	ds := &fakeFireStore{hosts: map[uint]*fleet.Host{
		7: {PrimaryMac: "50:54:46:00:5d:00"},
		8: {PrimaryMac: ""},
		9: {PrimaryMac: "AA:BB:CC:DD:EE:FF"},
	}}
	logger := slog.New(slog.DiscardHandler)
	RecordPolicyFireBatch(context.Background(), ds, logger, 2, []uint{7, 8, 9}, time.Now())
	require.Len(t, ds.upsert, 2)
}
