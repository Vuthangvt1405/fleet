package service

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/notifications/api"
	platform_errors "github.com/fleetdm/fleet/v4/server/platform/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMarkNotificationDisplayed(t *testing.T) {
	ctx := context.Background()
	logger := slog.New(slog.DiscardHandler)

	t.Run("acks the host's own pending notification", func(t *testing.T) {
		ds := &mockDatastore{storedNotification: &api.EndUserNotification{
			UUID: "uuid-1", HostID: 7, Kind: "message", Status: api.EndUserNotificationPending,
		}}

		require.NoError(t, NewService(ds, &mockScriptQueue{}, logger).MarkNotificationDisplayed(ctx, 7, "uuid-1"))

		assert.Equal(t, "uuid-1", ds.markedUUID)
		assert.Equal(t, uint(7), ds.markedHostID)
		assert.WithinDuration(t, time.Now().UTC(), ds.markedAt, time.Minute)
	})

	t.Run("another host's notification is not found and records nothing", func(t *testing.T) {
		ds := &mockDatastore{storedNotification: &api.EndUserNotification{
			UUID: "uuid-1", HostID: 7, Kind: "message", Status: api.EndUserNotificationPending,
		}}

		err := NewService(ds, &mockScriptQueue{}, logger).MarkNotificationDisplayed(ctx, 9, "uuid-1")
		require.Error(t, err)
		assert.True(t, platform_errors.IsNotFound(err))
		assert.Empty(t, ds.markedUUID)
	})
}
