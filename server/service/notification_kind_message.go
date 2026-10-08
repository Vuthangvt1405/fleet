package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/fleetdm/fleet/v4/server/contexts/ctxerr"
	"github.com/fleetdm/fleet/v4/server/fleet"
	notifications_api "github.com/fleetdm/fleet/v4/server/notifications/api"
)

const messageNotificationActionDismiss = "dismiss"

// messageNotificationKind renders admin-sent Messages page notifications.
// The payload carries the title and body; dismissing marks the notification
// acted so it does not resurface.
type messageNotificationKind struct {
	notificationSvc messageNotificationService
	logger          *slog.Logger
}

type messageNotificationService interface {
	notifications_api.ActOnNotificationService
}

func NewMessageNotificationKind(
	notificationSvc messageNotificationService,
	logger *slog.Logger,
) notifications_api.NotificationKind {
	return &messageNotificationKind{
		notificationSvc: notificationSvc,
		logger:          logger,
	}
}

func (k *messageNotificationKind) Name() string {
	return fleet.MessageNotificationKind
}

// DeliversViaScript reports whether the dispatch loop queues the shared
// notification script for this kind. Messages are polled for by Fleet
// Desktop directly, so their rows are never queued.
func (k *messageNotificationKind) DeliversViaScript() bool {
	return false
}

func messageNotificationPayload(notification *notifications_api.EndUserNotification) (fleet.MessageNotificationPayload, error) {
	var payload fleet.MessageNotificationPayload
	if err := json.Unmarshal(notification.Payload, &payload); err != nil {
		return payload, err
	}
	return payload, nil
}

func (k *messageNotificationKind) Render(ctx context.Context, notification *notifications_api.EndUserNotification) (*notifications_api.NotificationView, error) {
	payload, err := messageNotificationPayload(notification)
	if err != nil {
		return nil, ctxerr.Wrap(ctx, err, "read message notification payload")
	}
	if payload.Title == "" || payload.Body == "" {
		return nil, ctxerr.Errorf(ctx, "message notification %s has no title or body", notification.UUID)
	}

	return &notifications_api.NotificationView{
		UUID:        notification.UUID,
		Title:       payload.Title,
		Description: payload.Body,
		Actions: []notifications_api.NotificationAction{
			{ID: messageNotificationActionDismiss, Label: "Dismiss"},
		},
	}, nil
}

func (k *messageNotificationKind) OnVerify(_ context.Context, _ *notifications_api.EndUserNotification, _ time.Time) error {
	return nil
}

func (k *messageNotificationKind) OnDelay(_ context.Context, _ *notifications_api.EndUserNotification) (*notifications_api.NotificationView, error) {
	return nil, nil
}

func (k *messageNotificationKind) OnAction(ctx context.Context, notification *notifications_api.EndUserNotification, actionID string) (*notifications_api.NotificationView, error) {
	switch actionID {
	case messageNotificationActionDismiss:
		if _, err := k.notificationSvc.ActOnNotification(ctx, notification.UUID); err != nil {
			return nil, ctxerr.Wrap(ctx, err, "act on message notification")
		}
		return nil, nil

	default:
		return nil, ctxerr.Wrap(ctx, fleet.NewInvalidArgumentError("action",
			`"`+actionID+`" is not something that can be done to a message notification`))
	}
}

func (k *messageNotificationKind) OnOutcome(_ context.Context, _ *notifications_api.EndUserNotification, _ notifications_api.NotificationOutcome) error {
	return nil
}
