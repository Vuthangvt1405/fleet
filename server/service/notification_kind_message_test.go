package service

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	notifications_api "github.com/fleetdm/fleet/v4/server/notifications/api"
	"github.com/stretchr/testify/require"
)

type messageKindTestService struct {
	acted []string
}

func (m *messageKindTestService) ActOnNotification(_ context.Context, notificationUUID string) (bool, error) {
	m.acted = append(m.acted, notificationUUID)
	return true, nil
}

func newMessageTestNotification() *notifications_api.EndUserNotification {
	payload, _ := json.Marshal(map[string]string{
		"title":  "Blocked app detected",
		"body":   "Please uninstall uTorrent.",
		"sender": "Admin",
	})
	now := time.Now().UTC()
	return &notifications_api.EndUserNotification{
		UUID:      "test-uuid",
		HostID:    1,
		Status:    notifications_api.EndUserNotificationPending,
		Kind:      "message",
		Payload:   payload,
		ExpiresAt: &now,
		CreatedAt: now,
	}
}

func TestMessageNotificationKindName(t *testing.T) {
	kind := NewMessageNotificationKind(&messageKindTestService{}, slog.New(slog.DiscardHandler))
	require.Equal(t, "message", kind.Name())
}

func TestMessageNotificationKindRender(t *testing.T) {
	kind := NewMessageNotificationKind(&messageKindTestService{}, slog.New(slog.DiscardHandler))

	view, err := kind.Render(context.Background(), newMessageTestNotification())
	require.NoError(t, err)
	require.Equal(t, "test-uuid", view.UUID)
	require.Equal(t, "Blocked app detected", view.Title)
	require.Equal(t, "Please uninstall uTorrent.", view.Description)
	require.Len(t, view.Actions, 1)
	require.Equal(t, "dismiss", view.Actions[0].ID)
}

func TestMessageNotificationKindRenderBadPayload(t *testing.T) {
	kind := NewMessageNotificationKind(&messageKindTestService{}, slog.New(slog.DiscardHandler))

	notification := newMessageTestNotification()
	notification.Payload = json.RawMessage(`{"title":"","body":""}`)
	_, err := kind.Render(context.Background(), notification)
	require.Error(t, err)

	notification.Payload = json.RawMessage(`not json`)
	_, err = kind.Render(context.Background(), notification)
	require.Error(t, err)
}

func TestMessageNotificationKindDismiss(t *testing.T) {
	svc := &messageKindTestService{}
	kind := NewMessageNotificationKind(svc, slog.New(slog.DiscardHandler))

	view, err := kind.OnAction(context.Background(), newMessageTestNotification(), "dismiss")
	require.NoError(t, err)
	require.Nil(t, view)
	require.Equal(t, []string{"test-uuid"}, svc.acted)
}

func TestMessageNotificationKindUnknownAction(t *testing.T) {
	kind := NewMessageNotificationKind(&messageKindTestService{}, slog.New(slog.DiscardHandler))

	_, err := kind.OnAction(context.Background(), newMessageTestNotification(), "update_now")
	require.Error(t, err)
}

func TestMessageNotificationKindVerifyDelayOutcome(t *testing.T) {
	kind := NewMessageNotificationKind(&messageKindTestService{}, slog.New(slog.DiscardHandler))
	notification := newMessageTestNotification()

	require.NoError(t, kind.OnVerify(context.Background(), notification, time.Now().UTC()))

	view, err := kind.OnDelay(context.Background(), notification)
	require.NoError(t, err)
	require.Nil(t, view)

	require.NoError(t, kind.OnOutcome(context.Background(), notification, notifications_api.NotificationOutcome{}))
}
