package service

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/contexts/viewer"
	"github.com/fleetdm/fleet/v4/server/fleet"
	notifications_api "github.com/fleetdm/fleet/v4/server/notifications/api"
)

// messageHistoryLimit caps the Messages page history. History is small and
// read rarely; enrichment below is one host lookup per row.
const messageHistoryLimit = 100

////////////////////////////////////////////////////////////////////////////////
// Send Message to Host
////////////////////////////////////////////////////////////////////////////////

func sendMessageEndpoint(ctx context.Context, request interface{}, svc fleet.Service) (fleet.Errorer, error) {
	req := request.(*fleet.SendMessageRequest)

	message, err := svc.SendMessageToHost(ctx, req.HostID, req.Title, req.Body)
	if err != nil {
		return fleet.SendMessageResponse{Err: err}, nil
	}

	return fleet.SendMessageResponse{Message: *message}, nil
}

func (svc *Service) SendMessageToHost(ctx context.Context, hostID uint, title, body string) (*fleet.MessageNotification, error) {
	host, err := svc.ds.Host(ctx, hostID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "get host")
	}

	// Team-aware: team admins/maintainers/technicians may message their own hosts.
	if err := svc.authz.Authorize(ctx, host, fleet.ActionSendMessage); err != nil {
		return nil, err
	}

	if strings.TrimSpace(title) == "" {
		return nil, fleet.NewInvalidArgumentError("title", "missing required argument")
	}
	if strings.TrimSpace(body) == "" {
		return nil, fleet.NewInvalidArgumentError("body", "missing required argument")
	}

	vc, ok := viewer.FromContext(ctx)
	if !ok {
		return nil, fleet.ErrNoContext
	}

	payload, err := json.Marshal(fleet.MessageNotificationPayload{
		Title:  strings.TrimSpace(title),
		Body:   strings.TrimSpace(body),
		Sender: vc.FullName(),
	})
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "marshal message notification payload")
	}

	expiresAt := time.Now().UTC().Add(notifications_api.EndUserNotificationMaxLifetime)
	created, err := svc.notificationsSvc.CreateNotification(ctx, &notifications_api.EndUserNotification{
		HostID:    host.ID,
		Kind:      fleet.MessageNotificationKind,
		Payload:   payload,
		ExpiresAt: &expiresAt,
	})
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "create message notification")
	}

	return svc.messageFromNotification(ctx, created)
}

////////////////////////////////////////////////////////////////////////////////
// List Message History
////////////////////////////////////////////////////////////////////////////////

func listMessagesEndpoint(ctx context.Context, request interface{}, svc fleet.Service) (fleet.Errorer, error) {
	messages, err := svc.ListMessageNotifications(ctx)
	if err != nil {
		return fleet.ListMessagesResponse{Err: err}, nil
	}

	resp := make([]fleet.MessageNotification, 0, len(messages))
	for _, message := range messages {
		resp = append(resp, *message)
	}
	return fleet.ListMessagesResponse{Messages: resp}, nil
}

func (svc *Service) ListMessageNotifications(ctx context.Context) ([]*fleet.MessageNotification, error) {
	// Global history: any role that can list hosts (incl. observers) can read it.
	if err := svc.authz.Authorize(ctx, &fleet.Host{}, fleet.ActionList); err != nil {
		return nil, err
	}

	notifications, err := svc.notificationsSvc.ListEndUserNotificationsByKind(ctx, fleet.MessageNotificationKind, messageHistoryLimit)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "list message notifications")
	}

	messages := make([]*fleet.MessageNotification, 0, len(notifications))
	for _, notification := range notifications {
		message, err := svc.messageFromNotification(ctx, notification)
		if err != nil {
			return nil, err
		}
		messages = append(messages, message)
	}
	return messages, nil
}

// messageStatus maps end-user notification delivery state to the
// queued/sent/failed states the Messages page shows.
func messageStatus(notification *notifications_api.EndUserNotification) string {
	switch notification.Status {
	case notifications_api.EndUserNotificationPending:
		return fleet.MessageStatusQueued
	case notifications_api.EndUserNotificationDispatched,
		notifications_api.EndUserNotificationActed:
		return fleet.MessageStatusSent
	default:
		return fleet.MessageStatusFailed
	}
}

func (svc *Service) messageFromNotification(ctx context.Context, notification *notifications_api.EndUserNotification) (*fleet.MessageNotification, error) {
	var payload fleet.MessageNotificationPayload
	if err := json.Unmarshal(notification.Payload, &payload); err != nil {
		return nil, ctxerr.Wrap(ctx, err, "read message notification payload")
	}

	host, err := svc.ds.Host(ctx, notification.HostID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "get message notification host")
	}

	var userEmail string
	mappings, err := svc.ds.ListHostDeviceMapping(ctx, host.ID)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "list host device mapping")
	}
	if len(mappings) > 0 {
		userEmail = mappings[0].Email
	}

	return &fleet.MessageNotification{
		ID:         notification.ID,
		HostID:     host.ID,
		Hostname:   host.Hostname,
		UserEmail:  userEmail,
		Title:      payload.Title,
		Body:       payload.Body,
		Status:     messageStatus(notification),
		CreatedAt:  notification.CreatedAt,
		SenderName: payload.Sender,
	}, nil
}
