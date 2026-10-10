package fleet

import "time"

const MessageNotificationKind = "message"

// MessageNotificationPayload is the notifications_end_user.payload for
// notifications of kind "message" (sent from the Messages page).
type MessageNotificationPayload struct {
	Title      string `json:"title"`
	Body       string `json:"body"`
	Sender     string `json:"sender,omitempty"`
	Source     string `json:"source,omitempty"`
	PolicyID   uint   `json:"policy_id,omitempty"`
	PolicyName string `json:"policy_name,omitempty"`
}

// MessageNotification is a message sent to a host. It is backed by a
// notifications_end_user row of kind "message" and listed on the Messages
// page as send history.
type MessageNotification struct {
	ID         uint      `json:"id"`
	HostID     uint      `json:"host_id"`
	Hostname   string    `json:"hostname"`
	UserEmail  string    `json:"user_email,omitempty"`
	Title      string    `json:"title"`
	Body       string    `json:"body"`
	Status     string    `json:"status"`
	CreatedAt  time.Time `json:"created_at"`
	SenderName string    `json:"sender_name,omitempty"`
	Source     string    `json:"source,omitempty"`
	PolicyID   uint      `json:"policy_id,omitempty"`
	PolicyName string    `json:"policy_name,omitempty"`
}

// Message notification statuses as exposed to API clients.
const (
	MessageStatusQueued = "queued"
	MessageStatusSent   = "sent"
	MessageStatusFailed = "failed"
)
