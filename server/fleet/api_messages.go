package fleet

////////////////////////////////////////////////////////////////////////////////
// Send Message to Host
////////////////////////////////////////////////////////////////////////////////

type SendMessageRequest struct {
	HostID uint   `json:"host_id"`
	Title  string `json:"title"`
	Body   string `json:"body"`
}

type SendMessageResponse struct {
	Message MessageNotification `json:"message"`
	Err     error               `json:"error,omitempty"`
}

func (r SendMessageResponse) Error() error { return r.Err }

////////////////////////////////////////////////////////////////////////////////
// List Message History
////////////////////////////////////////////////////////////////////////////////

type ListMessagesRequest struct {
	// No parameters in v1. History returns the newest messages first,
	// capped server-side.
}

type ListMessagesResponse struct {
	Messages []MessageNotification `json:"messages"`
	Err      error                 `json:"error,omitempty"`
}

func (r ListMessagesResponse) Error() error { return r.Err }
