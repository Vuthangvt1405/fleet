package packetfence

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/url"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/fleet"
	notifications_api "github.com/fleetdm/fleet/v4/server/notifications/api"
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
	cpy.ID = 501
	s.upsert = append(s.upsert, &cpy)
	return &cpy, nil
}

type fakeNotificationCreator struct {
	notifications []*notifications_api.EndUserNotification
	err           error
}

func (f *fakeNotificationCreator) CreateNotification(_ context.Context, notification *notifications_api.EndUserNotification) (*notifications_api.EndUserNotification, error) {
	if f.err != nil {
		return nil, f.err
	}
	copy := *notification
	f.notifications = append(f.notifications, &copy)
	return &copy, nil
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

func TestIsPacketFenceWebhook(t *testing.T) {
	webhookURL, err := url.Parse("https://pf.example.com/fleet/webhook")
	require.NoError(t, err)
	require.True(t, IsPacketFenceWebhook(webhookURL, "https://pf.example.com"))
	require.False(t, IsPacketFenceWebhook(webhookURL, "https://other.example.com"))
	require.False(t, IsPacketFenceWebhook(webhookURL, "http://pf.example.com"))
	require.False(t, IsPacketFenceWebhook(nil, "https://pf.example.com"))
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
	finding, err := RecordPolicyFire(context.Background(), ds, 2, 7, fired)
	require.NoError(t, err)
	require.NotNil(t, finding)
	require.Equal(t, uint(501), finding.ID)
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
	finding, err := RecordPolicyFire(context.Background(), ds, 99, 7, time.Now())
	require.NoError(t, err)
	require.Nil(t, finding)
	require.Empty(t, ds.upsert)
}

func TestRecordPolicyFireMissingMAC(t *testing.T) {
	ds := &fakeFireStore{hosts: map[uint]*fleet.Host{
		7: {PrimaryMac: "  "},
	}}
	_, err := RecordPolicyFire(context.Background(), ds, 2, 7, time.Now())
	require.Error(t, err)
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

func TestQueuePolicyFireNotificationIncludesReasonAndIsIdempotent(t *testing.T) {
	creator := &fakeNotificationCreator{}
	finding := &fleet.PfRevocationFinding{ID: 501, HostID: 7}
	resolution := "Turn on Windows Firewall."
	policy := &fleet.Policy{PolicyData: fleet.PolicyData{ID: 2, Name: "Firewall enabled", Resolution: &resolution}}
	settings := &fleet.PacketFenceIntegration{
		NotifyEndUsers:                true,
		NotificationTitle:             "Action needed: {policy_name}",
		NotificationAdditionalMessage: "Contact IT if this is unexpected.",
	}
	firedAt := time.Now().UTC()

	require.NoError(t, QueuePolicyFireNotification(context.Background(), creator, finding, policy, settings, firedAt))
	require.Len(t, creator.notifications, 1)
	queued := creator.notifications[0]
	require.NotEmpty(t, queued.UUID)
	require.Equal(t, uint(7), queued.HostID)
	require.Equal(t, fleet.MessageNotificationKind, queued.Kind)
	require.Equal(t, firedAt.Add(notifications_api.EndUserNotificationMaxLifetime), *queued.ExpiresAt)

	var payload fleet.MessageNotificationPayload
	require.NoError(t, json.Unmarshal(queued.Payload, &payload))
	require.Equal(t, "Action needed: Firewall enabled", payload.Title)
	require.Contains(t, payload.Body, "This device failed the “Firewall enabled” policy.")
	require.Contains(t, payload.Body, "To resolve this, Turn on Windows Firewall.")
	require.Contains(t, payload.Body, "Contact IT if this is unexpected.")
	require.Equal(t, "automation", payload.Source)
	require.Equal(t, uint(2), payload.PolicyID)
	require.Equal(t, "Firewall enabled", payload.PolicyName)

	require.NoError(t, QueuePolicyFireNotification(context.Background(), creator, finding, policy, settings, firedAt))
	require.Equal(t, queued.UUID, creator.notifications[1].UUID)
}
