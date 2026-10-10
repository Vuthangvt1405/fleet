package service

import (
	"context"
	"net/http"

	"github.com/fleetdm/fleet/v4/server/contexts/viewer"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/service/externalsvc"
)

type testPacketFenceConnectionRequest struct {
	BaseURL  string `json:"base_url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type testPacketFenceConnectionResponse struct {
	Connected bool  `json:"connected"`
	Err       error `json:"error,omitempty"`
}

func (r testPacketFenceConnectionResponse) Error() error { return r.Err }

func testPacketFenceConnectionEndpoint(ctx context.Context, request interface{}, svc fleet.Service) (fleet.Errorer, error) {
	req := request.(*testPacketFenceConnectionRequest)
	err := svc.TestPacketFenceConnection(ctx, req.BaseURL, req.Username, req.Password)
	return testPacketFenceConnectionResponse{Connected: err == nil, Err: err}, nil
}

func (svc *Service) TestPacketFenceConnection(ctx context.Context, baseURL, username, password string) error {
	vc, ok := viewer.FromContext(ctx)
	if !ok || vc.User == nil || vc.User.GlobalRole == nil || *vc.User.GlobalRole != fleet.RoleAdmin {
		return fleet.NewPermissionError("Only a global admin can test the PacketFence connection.")
	}
	// Explicit authorization also prevents bypass through alternate auth methods.
	if err := svc.authz.Authorize(ctx, &fleet.AppConfig{}, fleet.ActionWrite); err != nil {
		return err
	}
	if password == fleet.MaskedPassword {
		stored, err := svc.ds.AppConfig(ctx)
		if err != nil {
			return err
		}
		pf := stored.Integrations.PacketFence
		if pf == nil || pf.BaseURL != baseURL || pf.Username != username || pf.Password == "" {
			return fleet.NewInvalidArgumentError("password", "a new password is required when changing the URL or username")
		}
		password = pf.Password
	}
	if baseURL == "" || username == "" || password == "" {
		return fleet.NewInvalidArgumentError("integrations.packetfence", "URL, username, and password are required")
	}
	client, err := externalsvc.NewPacketFenceClient(&externalsvc.PacketFenceOptions{
		BaseURL: baseURL, Username: username, Password: password,
	})
	if err != nil {
		return fleet.NewUserMessageError(err, http.StatusBadRequest)
	}
	if _, err := client.Login(ctx); err != nil {
		return fleet.NewUserMessageError(err, http.StatusBadRequest)
	}
	return nil
}
