package externalsvc

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func newPacketFenceTestServer(t *testing.T, handler http.HandlerFunc) (*PacketFence, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	// httptest serves http://; NewPacketFenceClient requires https. Tests run
	// through the constructor validation separately; here bypass it by
	// rewriting the scheme after validation via a direct struct build.
	cli, err := NewPacketFenceClient(&PacketFenceOptions{
		BaseURL:  "https://packetfence.example.com",
		Username: "u",
		Password: "p",
	})
	require.NoError(t, err)
	cli.opts.BaseURL = srv.URL
	return cli, srv
}

func TestNewPacketFenceClientValidation(t *testing.T) {
	_, err := NewPacketFenceClient(nil)
	require.Error(t, err)

	_, err = NewPacketFenceClient(&PacketFenceOptions{BaseURL: "http://pf.example.com", Username: "u", Password: "p"})
	require.ErrorContains(t, err, "HTTPS")

	_, err = NewPacketFenceClient(&PacketFenceOptions{BaseURL: "https://pf.example.com", Username: "", Password: ""})
	require.Error(t, err)

	cli, err := NewPacketFenceClient(&PacketFenceOptions{BaseURL: "https://pf.example.com/", Username: "u", Password: "p"})
	require.NoError(t, err)
	require.Equal(t, "https://pf.example.com", cli.opts.BaseURL)
	require.Equal(t, defaultClosedEventLookback, cli.opts.ClosedEventLookback)
}

func pfHandler(loginToken string, searchBody string, seen *[]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if seen != nil {
			*seen = append(*seen, r.Method+" "+r.URL.Path)
		}
		switch {
		case r.URL.Path == "/api/v1/login":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"token":"` + loginToken + `"}`))
		case r.URL.Path == "/api/v1/security_events/search":
			// Proven Python client sends the raw login token.
			if got := r.Header.Get("Authorization"); got != loginToken {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"status":401}`))
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(searchBody))
		case strings.HasSuffix(r.URL.Path, "/close_security_event"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":200}`))
		case strings.HasSuffix(r.URL.Path, "/reevaluate_access"):
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"200"}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestPacketFenceFindOpenEvent(t *testing.T) {
	search := `{"status":200,"items":[
		{"id":123,"mac":"AA:BB:CC:DD:EE:FF","security_event_id":"3500001","status":"open","release_date":"0000-00-00 00:00:00"},
		{"id":122,"mac":"AA:BB:CC:DD:EE:FF","security_event_id":"3500001","status":"closed","release_date":"2024-05-01 10:00:00"}
	]}`
	cli, _ := newPacketFenceTestServer(t, pfHandler("tok123", search, nil))
	id, isOpen, err := cli.FindMatchingEvent(context.Background(), "tok123", "aa:bb:cc:dd:ee:ff", "3500001")
	require.NoError(t, err)
	require.True(t, isOpen)
	require.Equal(t, "123", id)
}

func TestPacketFenceFindRecentlyClosed(t *testing.T) {
	cli, _ := newPacketFenceTestServer(t, pfHandler("tok", `{"status":"200","items":[
		{"id":"99","mac":"AA:BB:CC:DD:EE:FF","security_event_id":3500001,"status":"closed","release_date":"`+time.Now().UTC().Format(packetFenceReleaseDateLayout)+`"}
	]}`, nil))
	cli.now = time.Now
	id, isOpen, err := cli.FindMatchingEvent(context.Background(), "tok", "AA:BB:CC:DD:EE:FF", "3500001")
	require.NoError(t, err)
	require.False(t, isOpen)
	require.Equal(t, "99", id)
}

func TestPacketFenceFindNotFound(t *testing.T) {
	cli, _ := newPacketFenceTestServer(t, pfHandler("tok", `{"status":200,"items":[]}`, nil))
	_, _, err := cli.FindMatchingEvent(context.Background(), "tok", "AA:BB:CC:DD:EE:FF", "3500001")
	require.Error(t, err)
	require.True(t, errors.Is(err, ErrPacketFenceEventNotFound))
}

func TestPacketFenceVerifyClosed(t *testing.T) {
	openSearch := `{"items":[{"id":"1","mac":"AA:BB:CC:DD:EE:FF","security_event_id":"3500001","status":"open"}]}`
	cli, _ := newPacketFenceTestServer(t, pfHandler("tok", openSearch, nil))
	closed, err := cli.VerifyClosed(context.Background(), "tok", "AA:BB:CC:DD:EE:FF", "3500001")
	require.NoError(t, err)
	require.False(t, closed)

	closedSearch := `{"items":[{"id":"1","mac":"AA:BB:CC:DD:EE:FF","security_event_id":"3500001","status":"closed"}]}`
	cli2, _ := newPacketFenceTestServer(t, pfHandler("tok", closedSearch, nil))
	closed, err = cli2.VerifyClosed(context.Background(), "tok", "AA:BB:CC:DD:EE:FF", "3500001")
	require.NoError(t, err)
	require.True(t, closed)
}

func TestPacketFenceRecoverSequence(t *testing.T) {
	var seen []string
	search := `{"status":200,"items":[{"id":"12345","mac":"AA:BB:CC:DD:EE:FF","security_event_id":"3500001","status":"open"}]}`
	cli, _ := newPacketFenceTestServer(t, pfHandler("tok123", search, &seen))
	require.NoError(t, cli.Recover(context.Background(), "AA:BB:CC:DD:EE:FF", "3500001"))
	require.Equal(t, []string{
		"POST /api/v1/login",
		"POST /api/v1/security_events/search",
		"PUT /api/v1/node/AA:BB:CC:DD:EE:FF/close_security_event",
		"PUT /api/v1/node/AA:BB:CC:DD:EE:FF/reevaluate_access",
	}, seen)
}

func TestPacketFenceLoginFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(srv.Close)
	cli, err := NewPacketFenceClient(&PacketFenceOptions{BaseURL: "https://pf.example.com", Username: "u", Password: "p"})
	require.NoError(t, err)
	cli.opts.BaseURL = srv.URL
	_, err = cli.Login(context.Background())
	require.ErrorContains(t, err, "login failed")
}
