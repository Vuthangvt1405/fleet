// Package http provides the request and response types for the notifications
// endpoints.
package http

import (
	"github.com/fleetdm/fleet/v4/server/notifications/api"
)

type GetNotificationRequest struct {
	Token string `url:"token"`
	UUID  string `url:"uuid"`
}

// DeviceAuthToken is where the device auth middleware reads the token from.
func (r *GetNotificationRequest) DeviceAuthToken() string {
	return r.Token
}

type GetNotificationResponse struct {
	*api.NotificationView
	Err error `json:"error,omitempty"`
}

func (r GetNotificationResponse) Error() error { return r.Err }

type NotificationActionRequest struct {
	Token string `url:"token"`
	UUID  string `url:"uuid"`
	api.EndUserNotificationAction
}

// DeviceAuthToken is where the device auth middleware reads the token from.
func (r *NotificationActionRequest) DeviceAuthToken() string {
	return r.Token
}

type NotificationActionResponse struct {
	*api.NotificationView
	Err error `json:"error,omitempty"`
}

func (r NotificationActionResponse) Error() error { return r.Err }

type ListNotificationsRequest struct {
	Token string `url:"token"`
}

// DeviceAuthToken is where the device auth middleware reads the token from.
func (r *ListNotificationsRequest) DeviceAuthToken() string {
	return r.Token
}

type ListNotificationsResponse struct {
	Notifications []api.ListedNotification `json:"notifications"`
	Err           error                    `json:"error,omitempty"`
}

func (r ListNotificationsResponse) Error() error { return r.Err }

type MarkNotificationDisplayedRequest struct {
	Token string `url:"token"`
	UUID  string `url:"uuid"`
}

// DeviceAuthToken is where the device auth middleware reads the token from.
func (r *MarkNotificationDisplayedRequest) DeviceAuthToken() string {
	return r.Token
}

type MarkNotificationDisplayedResponse struct {
	Err error `json:"error,omitempty"`
}

func (r MarkNotificationDisplayedResponse) Error() error { return r.Err }
