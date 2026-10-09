package packetfence

import (
	"testing"

	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/stretchr/testify/require"
)

func TestConfigFromAppConfig(t *testing.T) {
	require.False(t, ConfigFromAppConfig(nil).Enabled)
	p := &fleet.PacketFenceIntegration{
		BaseURL: "https://pf.example.com", Username: "fleet", Password: "private", Enabled: true,
		ManagedEventTypes: []string{"3500001"}, RequireExclusiveOwnership: true,
		PolicyChecksRequired: 2, CVEChecksRequired: 1, DryRun: true,
	}
	cfg := ConfigFromAppConfig(p)
	require.True(t, cfg.Enabled)
	require.True(t, cfg.DryRun)
	require.Equal(t, []string{"3500001"}, cfg.ManagedEventTypes)
	p.RequireExclusiveOwnership = false
	require.False(t, ConfigFromAppConfig(p).Enabled)
	p.RequireExclusiveOwnership = true
	p.ManagedEventTypes = nil
	require.False(t, ConfigFromAppConfig(p).Enabled)
}
