package main

import (
	"math/rand"
	"sync"
	"sync/atomic"
	"time"

	fleetclient "github.com/fleetdm/fleet/v4/client"
	"github.com/fleetdm/fleet/v4/orbit/pkg/toast"
	"github.com/rs/zerolog/log"
)

const (
	messageToastGroup = "fleet-desktop-messages"
	// messagePollInterval is how often Fleet Desktop asks Fleet for pending
	// message notifications. Jittered at startup so the fleet doesn't tick together.
	messagePollInterval = 20 * time.Second
	// messageToastLifetime matches the server's maximum notification lifetime.
	messageToastLifetime = 24 * time.Hour
	messageToastButton   = "View device"
)

// messageNotificationClient is the device API surface the message poller needs.
type messageNotificationClient interface {
	ListNotifications(token string) ([]fleetclient.DeviceNotificationSummary, error)
	GetNotificationView(token, uuid string) (*fleetclient.DeviceNotificationView, error)
	MarkNotificationDisplayed(token, uuid string) error
	BrowserDeviceURL(token string) string
}

// messageToast polls Fleet for admin-sent message notifications and shows
// each as a Windows toast: popup on first sight, silent on repeats. It runs
// in Fleet Desktop (the user's session), which is what can toast. Rows the
// server no longer lists are forgotten, so the sets below stay small.
type messageToast struct {
	client messageNotificationClient
	token  func() string
	show   func(toast.Notification) error

	submitted atomic.Uint64

	mu        sync.Mutex
	lastCheck time.Time
	// seen UUIDs got at least one show attempt; displayed UUIDs reported back.
	seen      map[string]bool
	displayed map[string]bool
}

func newMessageToast(client messageNotificationClient, token func() string) *messageToast {
	return &messageToast{
		client: client,
		token:  token,
		show:   toast.Show,
		// Spread the first poll so the fleet doesn't tick together.
		lastCheck: time.Now().Add(-time.Duration(rand.Int63n(int64(messagePollInterval)))),
		seen:      make(map[string]bool),
		displayed: make(map[string]bool),
	}
}

// poll checks for new messages at most every messagePollInterval, in the
// background like the BitLocker toast: PowerShell can take seconds to start.
// Waiting for the lock does not preserve order, so an update that gets it
// after a newer poll started is dropped.
func (t *messageToast) poll() {
	t.mu.Lock()
	if time.Since(t.lastCheck) < messagePollInterval {
		t.mu.Unlock()
		return
	}
	t.lastCheck = time.Now()
	seq := t.submitted.Add(1)
	t.mu.Unlock()

	go func() {
		t.mu.Lock()
		defer t.mu.Unlock()
		if seq != t.submitted.Load() {
			return
		}
		t.reconcile()
	}()
}

// reconcile shows every pending message notification the server lists. The
// caller holds the lock.
func (t *messageToast) reconcile() {
	token := t.token()
	if token == "" {
		return
	}

	listed, err := t.client.ListNotifications(token)
	if err != nil {
		log.Error().Err(err).Msg("list message notifications failed")
		return
	}
	listedSet := make(map[string]bool, len(listed))
	for _, notification := range listed {
		listedSet[notification.UUID] = true
		if notification.Kind != "message" {
			continue
		}
		if t.displayed[notification.UUID] {
			continue
		}
		t.showOne(token, notification.UUID)
	}

	// Forget what the server no longer lists, and cap the silent-repeat set.
	for uuid := range t.displayed {
		if !listedSet[uuid] {
			delete(t.displayed, uuid)
			delete(t.seen, uuid)
		}
	}
	if len(t.seen) > 500 {
		for uuid := range t.seen {
			if !listedSet[uuid] {
				delete(t.seen, uuid)
			}
		}
	}
}

// showOne toasts one notification and reports it displayed. The caller holds
// the lock. A repeat shows silently; failures are logged and retried on the
// next poll, and the row expires server-side if the host never shows it.
func (t *messageToast) showOne(token, uuid string) {
	view, err := t.client.GetNotificationView(token, uuid)
	if err != nil {
		log.Error().Err(err).Str("uuid", uuid).Msg("get message notification view failed")
		return
	}

	popup := !t.seen[uuid]
	err = t.show(toast.Notification{
		Tag:           uuid,
		Group:         messageToastGroup,
		Title:         view.Title,
		Body:          view.Description,
		ButtonLabel:   messageToastButton,
		URL:           t.client.BrowserDeviceURL(token),
		ExpiresIn:     messageToastLifetime,
		SuppressPopup: !popup,
		StayOnScreen:  true,
	})
	if err != nil {
		log.Error().Err(err).Str("uuid", uuid).Msg("show message toast failed")
		return
	}
	log.Info().Str("uuid", uuid).Bool("popup", popup).Msg("posted the message toast")
	t.seen[uuid] = true

	if err := t.client.MarkNotificationDisplayed(token, uuid); err != nil {
		log.Error().Err(err).Str("uuid", uuid).Msg("mark message notification displayed failed")
		return
	}
	t.displayed[uuid] = true
}
