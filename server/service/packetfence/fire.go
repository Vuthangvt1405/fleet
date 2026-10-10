// Package packetfence reconciles Fleet policy/CVE findings with PacketFence
// security events. This file covers the fire path: recording a ledger row
// when a Fleet automation webhook causes PacketFence to create an event.
//
// Scoped to the firewall policy first: Fleet policy ID 2
// ("Windows Firewall enabled on all profiles") maps to PacketFence event
// type 3500001. Other policies are ignored (no-op) until their mappings are
// defined.
package packetfence

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
)

const (
	// PfPolicyFirewallID is the Fleet policy that triggers isolation via
	// PacketFence event type 3500001.
	PfPolicyFirewallID = uint(2)
	// PfEventTypeFirewall is the PacketFence event type for the firewall policy.
	PfEventTypeFirewall = "3500001"
)

// PfEventTypeForPolicy returns the PacketFence event type for a Fleet policy.
// Scoped to 3500001 only; unknown policies report ok=false.
func PfEventTypeForPolicy(policyID uint) (string, bool) {
	if policyID == PfPolicyFirewallID {
		return PfEventTypeFirewall, true
	}
	return "", false
}

// NormalizeMAC canonicalizes a host MAC for ledger grouping: lowercase,
// colon-separated, trimmed. PacketFence comparisons are case-insensitive but
// the ledger groups by exact string, so all writers must use this.
func NormalizeMAC(mac string) string {
	m := strings.TrimSpace(mac)
	m = strings.ReplaceAll(m, "-", ":")
	m = strings.ReplaceAll(m, ".", ":")
	m = strings.ToLower(m)
	// Collapse surrounding whitespace around separators left by odd input.
	m = strings.Join(strings.Fields(m), "")
	return m
}

// FireStore is the narrow persistence contract the fire path needs. It is
// satisfied by fleet.Datastore via fleet.PacketFenceStore (Upsert) plus the
// host lookup.
type FireStore interface {
	Host(ctx context.Context, id uint) (*fleet.Host, error)
	UpsertPfRevocationFinding(ctx context.Context, f *fleet.PfRevocationFinding) (*fleet.PfRevocationFinding, error)
}

// RecordPolicyFire records one ledger row in pending_discovery after a policy
// automation webhook POST was accepted by the PacketFence receiver. It is a
// no-op for policies without a PacketFence mapping. A missing host MAC is an
// error so callers can log and skip without blocking the webhook itself.
func RecordPolicyFire(
	ctx context.Context,
	ds FireStore,
	policyID, hostID uint,
	firedAt time.Time,
) error {
	eventType, ok := PfEventTypeForPolicy(policyID)
	if !ok {
		return nil
	}
	host, err := ds.Host(ctx, hostID)
	if err != nil {
		return ctxerr.Wrap(ctx, err, "load host for pf fire")
	}
	mac := NormalizeMAC(host.PrimaryMac)
	if mac == "" {
		return ctxerr.New(ctx, "host has no primary MAC for pf fire")
	}
	pid := policyID
	_, err = ds.UpsertPfRevocationFinding(ctx, &fleet.PfRevocationFinding{
		HostID:      hostID,
		HostMAC:     mac,
		TriggerType: fleet.PfTriggerPolicy,
		PolicyID:    &pid,
		PfEventType: eventType,
		FiredAt:     firedAt,
		State:       fleet.PfStatePendingDiscovery,
	})
	if err != nil {
		return ctxerr.Wrap(ctx, err, "upsert pf revocation finding")
	}
	return nil
}

// RecordPolicyFireBatch records ledger rows for every successfully sent host.
// Per-host errors are logged and skipped; one bad host never blocks the rest.
func RecordPolicyFireBatch(
	ctx context.Context,
	ds FireStore,
	logger *slog.Logger,
	policyID uint,
	hostIDs []uint,
	firedAt time.Time,
) {
	if _, ok := PfEventTypeForPolicy(policyID); !ok {
		return
	}
	for _, hid := range hostIDs {
		if err := RecordPolicyFire(ctx, ds, policyID, hid, firedAt); err != nil {
			logger.WarnContext(ctx, "failed to record pf revocation finding",
				"policy_id", policyID, "host_id", hid, "err", err)
		}
	}
}
