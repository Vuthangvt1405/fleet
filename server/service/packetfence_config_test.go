package service

import (
	"context"
	"testing"

	"github.com/fleetdm/fleet/v4/server/contexts/viewer"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/mock"
	"github.com/fleetdm/fleet/v4/server/ptr"
	"github.com/stretchr/testify/require"
)

func TestPacketFenceConnectionRejectsStoredPasswordForOtherDestination(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &fleet.User{GlobalRole: ptr.String(fleet.RoleAdmin)}})
	ds.AppConfigFunc = func(context.Context) (*fleet.AppConfig, error) {
		return &fleet.AppConfig{Integrations: fleet.Integrations{PacketFence: &fleet.PacketFenceIntegration{
			BaseURL: "https://original.example.com", Username: "fleet", Password: "private",
		}}}, nil
	}
	require.Error(t, svc.TestPacketFenceConnection(ctx, "https://other.example.com", "fleet", fleet.MaskedPassword))
	require.Error(t, svc.TestPacketFenceConnection(ctx, "https://original.example.com", "other", fleet.MaskedPassword))
}

func TestPacketFenceConnectionRequiresGlobalAdmin(t *testing.T) {
	ds := new(mock.Store)
	svc, ctx := newTestService(t, ds, nil, nil)
	ctx = viewer.NewContext(ctx, viewer.Viewer{User: &fleet.User{GlobalRole: ptr.String(fleet.RoleMaintainer)}})
	require.Error(t, svc.TestPacketFenceConnection(ctx, "https://pf.example.com", "fleet", "private"))
}
