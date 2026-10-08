package main

import (
	"errors"
	"testing"

	fleetclient "github.com/fleetdm/fleet/v4/client"
	"github.com/fleetdm/fleet/v4/orbit/pkg/toast"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeMessageClient struct {
	listed    []fleetclient.DeviceNotificationSummary
	views     map[string]*fleetclient.DeviceNotificationView
	listErr   error
	viewErr   error
	displayed []string
}

func (f *fakeMessageClient) ListNotifications(_ string) ([]fleetclient.DeviceNotificationSummary, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	return f.listed, nil
}

func (f *fakeMessageClient) GetNotificationView(_, uuid string) (*fleetclient.DeviceNotificationView, error) {
	if f.viewErr != nil {
		return nil, f.viewErr
	}
	view, ok := f.views[uuid]
	if !ok {
		return nil, errors.New("no such notification")
	}
	return view, nil
}

func (f *fakeMessageClient) MarkNotificationDisplayed(_, uuid string) error {
	f.displayed = append(f.displayed, uuid)
	return nil
}

func (f *fakeMessageClient) BrowserDeviceURL(_ string) string {
	return "https://fleet.example.com/device/token"
}

func newMessageToastForTest(client *fakeMessageClient, show func(toast.Notification) error) *messageToast {
	t := newMessageToast(client, func() string { return "token" })
	t.show = show
	return t
}

func TestMessageToastPollsAndDisplays(t *testing.T) {
	t.Parallel()

	view := &fleetclient.DeviceNotificationView{
		UUID:        "uuid-1",
		Title:       "Blocked app detected",
		Description: "Please uninstall uTorrent.",
	}
	client := &fakeMessageClient{
		listed: []fleetclient.DeviceNotificationSummary{{UUID: "uuid-1", Kind: "message"}},
		views:  map[string]*fleetclient.DeviceNotificationView{"uuid-1": view},
	}

	type post struct {
		title string
		popup bool
	}
	var posts []post
	toaster := newMessageToastForTest(client, func(n toast.Notification) error {
		assert.Equal(t, "uuid-1", n.Tag)
		assert.Equal(t, messageToastGroup, n.Group)
		assert.Equal(t, "Blocked app detected", n.Title)
		assert.Equal(t, "Please uninstall uTorrent.", n.Body)
		posts = append(posts, post{title: n.Title, popup: !n.SuppressPopup})
		return nil
	})

	toaster.reconcile()
	toaster.reconcile()

	require.Equal(t, []post{{"Blocked app detected", true}}, posts)
	require.Equal(t, []string{"uuid-1"}, client.displayed)
}

func TestMessageToastSkipsNonMessageKinds(t *testing.T) {
	t.Parallel()

	client := &fakeMessageClient{
		listed: []fleetclient.DeviceNotificationSummary{{UUID: "uuid-9", Kind: "patch"}},
	}
	shown := 0
	toaster := newMessageToastForTest(client, func(toast.Notification) error {
		shown++
		return nil
	})

	toaster.reconcile()

	require.Zero(t, shown)
	require.Empty(t, client.displayed)
}

func TestMessageToastSkipsDisplayed(t *testing.T) {
	t.Parallel()

	view := &fleetclient.DeviceNotificationView{UUID: "uuid-1", Title: "T", Description: "B"}
	client := &fakeMessageClient{
		listed: []fleetclient.DeviceNotificationSummary{{UUID: "uuid-1", Kind: "message"}},
		views:  map[string]*fleetclient.DeviceNotificationView{"uuid-1": view},
	}
	shown := 0
	toaster := newMessageToastForTest(client, func(toast.Notification) error {
		shown++
		return nil
	})
	toaster.displayed["uuid-1"] = true

	toaster.reconcile()

	require.Zero(t, shown)
}

func TestMessageToastFailedShowRetriesWithPopup(t *testing.T) {
	t.Parallel()

	showErr := errors.New("PowerShell is blocked")
	view := &fleetclient.DeviceNotificationView{UUID: "uuid-1", Title: "T", Description: "B"}
	client := &fakeMessageClient{
		listed: []fleetclient.DeviceNotificationSummary{{UUID: "uuid-1", Kind: "message"}},
		views:  map[string]*fleetclient.DeviceNotificationView{"uuid-1": view},
	}
	var popups []bool
	fail := true
	toaster := newMessageToastForTest(client, func(n toast.Notification) error {
		popups = append(popups, !n.SuppressPopup)
		if fail {
			return showErr
		}
		return nil
	})

	toaster.reconcile()
	fail = false
	// Server still lists it (display was never reported), so the retry pops up again.
	client.listed = []fleetclient.DeviceNotificationSummary{{UUID: "uuid-1", Kind: "message"}}
	toaster.reconcile()

	require.Equal(t, []bool{true, true}, popups)
	require.Equal(t, []string{"uuid-1"}, client.displayed)
}

func TestMessageToastForgetsGoneRows(t *testing.T) {
	t.Parallel()

	view := &fleetclient.DeviceNotificationView{UUID: "uuid-1", Title: "T", Description: "B"}
	client := &fakeMessageClient{
		listed: []fleetclient.DeviceNotificationSummary{{UUID: "uuid-1", Kind: "message"}},
		views:  map[string]*fleetclient.DeviceNotificationView{"uuid-1": view},
	}
	toaster := newMessageToastForTest(client, func(toast.Notification) error { return nil })

	toaster.reconcile()
	require.True(t, toaster.displayed["uuid-1"])

	// Expired server-side: the next poll forgets it.
	client.listed = nil
	toaster.reconcile()
	require.Empty(t, toaster.displayed)
	require.Empty(t, toaster.seen)
}
