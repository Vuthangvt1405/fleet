package externalsvc

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/fleetdm/fleet/v4/pkg/fleethttp"
)

const (
	// defaultPacketFenceTimeout mirrors recovery.py's 10s transport timeout.
	defaultPacketFenceTimeout = 10 * time.Second
	// defaultClosedEventLookback mirrors recovery.py's 3600s window for
	// treating a recently-closed event as a match for reevaluate-only.
	defaultClosedEventLookback = time.Hour
	// packetFenceReleaseDateLayout is the PacketFence DB datetime format
	// (e.g. "2024-05-01 10:00:00"). Zero dates use "0000-00-00 00:00:00".
	packetFenceReleaseDateLayout = "2006-01-02 15:04:05"
)

// ErrPacketFenceEventNotFound is returned when no PacketFence security event
// matches (mac, event type).
var ErrPacketFenceEventNotFound = errors.New("no PacketFence event found for MAC and event type")

// PacketFenceOptions configures a PacketFence Unified API client.
//
// This is a Go port of the proven recovery.py PacketFenceClient behavior:
// login with username/password, search security events, close by instance ID,
// then reevaluate access. P0-1 scope only: primitives + VerifyClosed.
type PacketFenceOptions struct {
	// BaseURL is the PacketFence base URL, e.g. "https://pf.example.com".
	// HTTPS is required, matching recovery.py.
	BaseURL  string
	Username string
	Password string
	// ClosedEventLookback controls how recently a closed event must have been
	// released to count as a reevaluate-only match. Defaults to 1h.
	ClosedEventLookback time.Duration
	// Timeout for each HTTP request. Defaults to 10s.
	Timeout time.Duration
	// TLSConfig, when non-nil, configures the HTTP transport.
	TLSConfig *tls.Config
	// CAFile, when set, loads additional root CAs (lab CAs).
	CAFile string
	// AllowLegacyCA is accepted for parity with recovery.py's
	// allow_legacy_ca mode (chain + hostname verification stay enabled).
	// Go's verifier does not enforce OpenSSL VERIFY_X509_STRICT keyUsage
	// checks, so this is currently a no-op marker for config parity.
	AllowLegacyCA bool
	// ServerLocation interprets naive release_date timestamps. Nil means UTC.
	ServerLocation *time.Location
	// HTTPClient overrides the default fleethttp client (tests).
	HTTPClient *http.Client
}

// PacketFence is a PacketFence Unified API client.
type PacketFence struct {
	opts   PacketFenceOptions
	client *http.Client
	now    func() time.Time
}

// NewPacketFenceClient returns a PacketFence client.
func NewPacketFenceClient(opts *PacketFenceOptions) (*PacketFence, error) {
	if opts == nil {
		return nil, errors.New("packetfence options are required")
	}
	if strings.TrimSpace(opts.Username) == "" || strings.TrimSpace(opts.Password) == "" {
		return nil, errors.New("packetfence username and password are required")
	}
	base := strings.TrimRight(strings.TrimSpace(opts.BaseURL), "/")
	u, err := url.Parse(base)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("invalid packetfence base URL: %q", opts.BaseURL)
	}
	if u.Scheme != "https" {
		return nil, errors.New("packetfence base URL must use HTTPS")
	}
	lookback := opts.ClosedEventLookback
	if lookback == 0 {
		lookback = defaultClosedEventLookback
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = defaultPacketFenceTimeout
	}

	client := opts.HTTPClient
	if client == nil {
		var clientOpts []fleethttp.ClientOpt
		clientOpts = append(clientOpts, fleethttp.WithTimeout(timeout))
		if tlsConf, err := packetFenceTLSConfig(opts); err != nil {
			return nil, err
		} else if tlsConf != nil {
			clientOpts = append(clientOpts, fleethttp.WithTLSClientConfig(tlsConf))
		}
		client = fleethttp.NewClient(clientOpts...)
	}

	cpy := *opts
	cpy.BaseURL = base
	cpy.ClosedEventLookback = lookback
	cpy.Timeout = timeout
	return &PacketFence{opts: cpy, client: client, now: time.Now}, nil
}

func packetFenceTLSConfig(opts *PacketFenceOptions) (*tls.Config, error) {
	if opts.TLSConfig == nil && opts.CAFile == "" {
		return nil, nil
	}
	var conf *tls.Config
	if opts.TLSConfig != nil {
		conf = opts.TLSConfig.Clone()
	} else {
		conf = &tls.Config{} //nolint:gosec // MinVersion set below
	}
	conf.MinVersion = tls.VersionTLS12
	if opts.CAFile != "" {
		pem, err := os.ReadFile(opts.CAFile)
		if err != nil {
			return nil, fmt.Errorf("read packetfence CA file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("packetfence CA file contains no valid certificates")
		}
		conf.RootCAs = pool
	}
	return conf, nil
}

// flexStatus accepts PacketFence envelope statuses encoded as 200 or "200".
// Missing status is treated as 200, matching recovery.py's body.get default.
type flexStatus int

func (s *flexStatus) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*s = 200
		return nil
	}
	var n int
	if err := json.Unmarshal(b, &n); err == nil {
		*s = flexStatus(n)
		return nil
	}
	var str string
	if err := json.Unmarshal(b, &str); err != nil {
		return fmt.Errorf("invalid status value %s", string(b))
	}
	var parsed int
	if _, err := fmt.Sscanf(strings.TrimSpace(str), "%d", &parsed); err != nil {
		return fmt.Errorf("invalid status value %q", str)
	}
	*s = flexStatus(parsed)
	return nil
}

// flexID accepts IDs encoded as JSON numbers or strings.
type flexID string

func (id *flexID) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		*id = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		*id = flexID(s)
		return nil
	}
	var n json.Number
	if err := json.Unmarshal(b, &n); err != nil {
		return fmt.Errorf("invalid id value %s", string(b))
	}
	*id = flexID(n.String())
	return nil
}

// SecurityEvent is a subset of PacketFence security-event search fields.
type SecurityEvent struct {
	ID              flexID `json:"id"`
	MAC             string `json:"mac"`
	SecurityEventID flexID `json:"security_event_id"`
	Status          string `json:"status"`
	ReleaseDate     string `json:"release_date"`
	StartDate       string `json:"start_date"`
}

type pfSearchRequest struct {
	Fields []string `json:"fields"`
	Limit  int      `json:"limit"`
	Cursor int      `json:"cursor"`
	Query  pfQuery  `json:"query"`
	Sort   []string `json:"sort"`
}

type pfQuery struct {
	Op     string     `json:"op"`
	Values []pfClause `json:"values"`
}

type pfClause struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

type pfSearchResponse struct {
	Status *flexStatus     `json:"status"`
	Items  []SecurityEvent `json:"items"`
}

type pfLoginResponse struct {
	Status *flexStatus `json:"status"`
	Token  string      `json:"token"`
}

func pfStatusOK(s *flexStatus) bool {
	if s == nil {
		return true
	}
	return *s == 200
}

// escapeMAC preserves colons, matching Python's quote(mac, safe=":").
func escapeMAC(mac string) string {
	e := url.PathEscape(mac)
	e = strings.ReplaceAll(e, "%3A", ":")
	e = strings.ReplaceAll(e, "%3a", ":")
	return e
}

func (p *PacketFence) doJSON(ctx context.Context, method, path string, payload any, token string, out any) (int, error) {
	var body io.Reader
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, fmt.Errorf("marshal packetfence request: %w", err)
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.opts.BaseURL+path, body)
	if err != nil {
		return 0, fmt.Errorf("build packetfence request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	// Proven recovery.py behavior sends the login token raw in the
	// Authorization header (no "Bearer " prefix). Send as-is to preserve
	// compat; a token that already carries a scheme prefix is left untouched.
	if token != "" {
		req.Header.Set("Authorization", token)
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("packetfence request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return resp.StatusCode, fmt.Errorf("read packetfence response: %w", err)
	}
	if out != nil && len(bytes.TrimSpace(raw)) > 0 {
		if err := json.Unmarshal(raw, out); err != nil {
			return resp.StatusCode, fmt.Errorf("decode packetfence response %s %s: %w", method, path, err)
		}
	}
	return resp.StatusCode, nil
}

// Login authenticates and returns the API token.
func (p *PacketFence) Login(ctx context.Context) (string, error) {
	var lr pfLoginResponse
	status, err := p.doJSON(ctx, http.MethodPost, "/api/v1/login", map[string]string{
		"username": p.opts.Username,
		"password": p.opts.Password,
	}, "", &lr)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK || !pfStatusOK(lr.Status) || lr.Token == "" {
		return "", fmt.Errorf("packetfence login failed with HTTP %d", status)
	}
	return lr.Token, nil
}

// SearchEvents returns matching events for (mac, event type), newest first.
func (p *PacketFence) SearchEvents(ctx context.Context, token, mac, eventType string) ([]SecurityEvent, error) {
	req := pfSearchRequest{
		Fields: []string{"id", "status", "mac", "security_event_id", "release_date", "start_date"},
		Limit:  100,
		Cursor: 0,
		Query: pfQuery{
			Op: "and",
			Values: []pfClause{
				{Field: "mac", Op: "equals", Value: mac},
				{Field: "security_event_id", Op: "equals", Value: eventType},
			},
		},
		Sort: []string{"id DESC"},
	}
	var sr pfSearchResponse
	status, err := p.doJSON(ctx, http.MethodPost, "/api/v1/security_events/search", req, token, &sr)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK || !pfStatusOK(sr.Status) {
		return nil, fmt.Errorf("packetfence security-event search failed with HTTP %d", status)
	}
	return sr.Items, nil
}

// FindMatchingEvent ports recovery.py _find_matching_event: prefers an open
// event; otherwise returns a recently-closed event for reevaluate-only.
// Returns ErrPacketFenceEventNotFound when neither exists.
func (p *PacketFence) FindMatchingEvent(ctx context.Context, token, mac, eventType string) (eventID string, isOpen bool, err error) {
	items, err := p.SearchEvents(ctx, token, mac, eventType)
	if err != nil {
		return "", false, err
	}
	var closedID string
	for _, e := range items {
		if !strings.EqualFold(e.MAC, mac) || string(e.SecurityEventID) != eventType {
			continue
		}
		if e.Status == "open" {
			return string(e.ID), true, nil
		}
		if e.Status == "closed" && closedID == "" && p.isRecentlyClosed(e.ReleaseDate) {
			closedID = string(e.ID)
		}
	}
	if closedID != "" {
		return closedID, false, nil
	}
	return "", false, fmt.Errorf("%w: event %s for MAC %s", ErrPacketFenceEventNotFound, eventType, mac)
}

func (p *PacketFence) isRecentlyClosed(releaseDate string) bool {
	v := strings.TrimSpace(releaseDate)
	if v == "" || v == "0000-00-00 00:00:00" {
		return false
	}
	t, err := time.ParseInLocation(packetFenceReleaseDateLayout, v, p.serverLocation())
	if err != nil {
		return false
	}
	age := p.now().Sub(t)
	return age >= 0 && age <= p.opts.ClosedEventLookback
}

func (p *PacketFence) serverLocation() *time.Location {
	if p.opts.ServerLocation != nil {
		return p.opts.ServerLocation
	}
	return time.UTC
}

// CloseEvent closes a security-event instance for a MAC. instanceID is the
// PacketFence DB row ID from search, not the configured event type ID.
func (p *PacketFence) CloseEvent(ctx context.Context, token, mac, instanceID string) error {
	var body map[string]any
	status, err := p.doJSON(ctx, http.MethodPut,
		"/api/v1/node/"+escapeMAC(mac)+"/close_security_event",
		map[string]string{"security_event_id": instanceID}, token, &body)
	if err != nil {
		return err
	}
	if status != http.StatusOK || !pfBodyStatusOK(body) {
		return fmt.Errorf("packetfence close_security_event failed: HTTP %d", status)
	}
	return nil
}

// ReevaluateAccess asks PacketFence to reevaluate device network access.
// The close controller already triggers reevaluation; keep this as an
// optional compat/recovery step per the proven recovery.py sequence.
func (p *PacketFence) ReevaluateAccess(ctx context.Context, token, mac string) error {
	var body map[string]any
	status, err := p.doJSON(ctx, http.MethodPut,
		"/api/v1/node/"+escapeMAC(mac)+"/reevaluate_access", nil, token, &body)
	if err != nil {
		return err
	}
	if status != http.StatusOK || !pfBodyStatusOK(body) {
		return fmt.Errorf("packetfence reevaluate_access failed: HTTP %d", status)
	}
	return nil
}

// VerifyClosed reports true only when no non-closed record remains for
// (mac, event type). Never trust HTTP success alone.
func (p *PacketFence) VerifyClosed(ctx context.Context, token, mac, eventType string) (bool, error) {
	items, err := p.SearchEvents(ctx, token, mac, eventType)
	if err != nil {
		return false, err
	}
	for _, e := range items {
		if !strings.EqualFold(e.MAC, mac) || string(e.SecurityEventID) != eventType {
			continue
		}
		if e.Status != "closed" {
			return false, nil
		}
	}
	return true, nil
}

// Recover ports recovery.py recover(): login, close the open event if any,
// then always reevaluate access. Recently-closed matches skip the close but
// still trigger reevaluation.
func (p *PacketFence) Recover(ctx context.Context, mac, eventType string) error {
	token, err := p.Login(ctx)
	if err != nil {
		return err
	}
	eventID, isOpen, err := p.FindMatchingEvent(ctx, token, mac, eventType)
	if err != nil {
		return err
	}
	if isOpen {
		if err := p.CloseEvent(ctx, token, mac, eventID); err != nil {
			return err
		}
	}
	return p.ReevaluateAccess(ctx, token, mac)
}

func pfBodyStatusOK(body map[string]any) bool {
	if body == nil {
		return true
	}
	v, ok := body["status"]
	if !ok {
		return true
	}
	switch t := v.(type) {
	case float64:
		return t == 200
	case int:
		return t == 200
	case string:
		var n int
		if _, err := fmt.Sscanf(strings.TrimSpace(t), "%d", &n); err == nil {
			return n == 200
		}
		return false
	default:
		return false
	}
}
