package fleet

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPacketFenceConfigMaskAndCopy(t *testing.T) {
	original := &AppConfig{Integrations: Integrations{PacketFence: &PacketFenceIntegration{
		BaseURL: "https://pf.example.com", Password: "private", ManagedEventTypes: []string{"3500001"},
	}}}
	clone := original.Copy()
	clone.Obfuscate()
	require.Equal(t, MaskedPassword, clone.Integrations.PacketFence.Password)
	clone.Integrations.PacketFence.ManagedEventTypes[0] = "changed"
	require.Equal(t, "private", original.Integrations.PacketFence.Password)
	require.Equal(t, "3500001", original.Integrations.PacketFence.ManagedEventTypes[0])
}

func TestValidatePacketFenceIntegration(t *testing.T) {
	valid := &PacketFenceIntegration{
		BaseURL: "https://pf.example.com", Username: "fleet", Password: "private", Enabled: true,
		ManagedEventTypes: []string{"3500001"}, RequireExclusiveOwnership: true,
		PolicyChecksRequired: 2, CVEChecksRequired: 1,
	}
	invalid := &InvalidArgumentError{}
	ValidatePacketFenceIntegration(valid, invalid)
	require.False(t, invalid.HasErrors())
	valid.RequireExclusiveOwnership = false
	invalid = &InvalidArgumentError{}
	ValidatePacketFenceIntegration(valid, invalid)
	require.True(t, invalid.HasErrors())
	valid.RequireExclusiveOwnership = true
	valid.ManagedEventTypes = []string{"3500001", "3500001"}
	invalid = &InvalidArgumentError{}
	ValidatePacketFenceIntegration(valid, invalid)
	require.True(t, invalid.HasErrors())
}
