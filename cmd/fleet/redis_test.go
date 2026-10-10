package main

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/fleetdm/fleet/v4/server/config"
	"github.com/fleetdm/fleet/v4/server/datastore/cached_mysql"
	"github.com/fleetdm/fleet/v4/server/datastore/etag_invalidate"
	"github.com/fleetdm/fleet/v4/server/datastore/mysql"
	"github.com/fleetdm/fleet/v4/server/datastore/mysqlredis"
	"github.com/fleetdm/fleet/v4/server/fleet"
	"github.com/fleetdm/fleet/v4/server/service/packetfence"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The raw MySQL datastore implements the PacketFence contracts as part of
// fleet.Datastore, so the decorators promote them to the fully wrapped
// datastore handed to cron. These assertions pin both ends of that promise.
var (
	_ packetfence.LedgerStore   = (*mysql.Datastore)(nil)
	_ packetfence.PolicyChecker = (*mysql.Datastore)(nil)
	_ packetfence.CVEChecker    = (*mysql.Datastore)(nil)
	_ fleet.PacketFenceStore    = (*mysql.Datastore)(nil)
)

// fleet.Datastore itself must satisfy the reconciler's narrow contracts;
// otherwise the cron type assertions can fail on a valid datastore.
var (
	_ packetfence.LedgerStore   = (fleet.Datastore)(nil)
	_ packetfence.PolicyChecker = (fleet.Datastore)(nil)
	_ packetfence.CVEChecker    = (fleet.Datastore)(nil)
)

func TestPacketFenceDatastoreWrappedForCron(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	for _, tc := range []struct {
		name string
		etag bool
	}{
		{"ETag off", false},
		{"ETag on", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Match the initRedis construction order, with the actual MySQL
			// datastore and production decorators (no database/Redis I/O needed).
			raw := &mysql.Datastore{}
			redisDS := mysqlredis.New(cached_mysql.New(raw), nil)
			var ds fleet.Datastore = redisDS
			if tc.etag {
				ds = etag_invalidate.New(redisDS, nil, logger)
			}
			_, ok := ds.(packetfence.LedgerStore)
			assert.True(t, ok)
			_, ok = ds.(packetfence.PolicyChecker)
			assert.True(t, ok)
			_, ok = ds.(packetfence.CVEChecker)
			assert.True(t, ok)

			// These are the same assertions used at the cron handoff.
			schedule, err := newPacketFenceRevocationSchedule(context.Background(), "test", ds, logger, true)
			require.NoError(t, err)
			require.NotNil(t, schedule)
		})
	}
}

type packetFenceForwardingStore struct {
	fleet.Datastore
	called []string
}

func (s *packetFenceForwardingStore) ListPfRevocationDue(context.Context, time.Time, int) ([]*fleet.PfRevocationFinding, error) {
	s.called = append(s.called, "due")
	return nil, nil
}

func (s *packetFenceForwardingStore) ListPfRevocationGroup(context.Context, string, string) ([]*fleet.PfRevocationFinding, error) {
	s.called = append(s.called, "group")
	return nil, nil
}

func (s *packetFenceForwardingStore) UpdatePfRevocationFinding(context.Context, *fleet.PfRevocationFinding) error {
	s.called = append(s.called, "update")
	return nil
}

func (s *packetFenceForwardingStore) MarkPfGroupClearedFromClearing(context.Context, string, string, int64) (bool, error) {
	s.called = append(s.called, "clear")
	return true, nil
}

func (s *packetFenceForwardingStore) CheckPfPolicyCompliance(context.Context, uint, uint) (fleet.PfObservation, error) {
	s.called = append(s.called, "policy")
	return fleet.PfObservation{}, nil
}

func (s *packetFenceForwardingStore) CheckPfCVECompliance(context.Context, uint, string, time.Time) (fleet.PfObservation, error) {
	s.called = append(s.called, "cve")
	return fleet.PfObservation{}, nil
}

func TestPacketFenceDatastoreDelegatesAllCapabilities(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)
	for _, tc := range []struct {
		name string
		etag bool
	}{
		{"ETag off", false},
		{"ETag on", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := &packetFenceForwardingStore{}
			redisDS := mysqlredis.New(cached_mysql.New(raw), nil)
			var ds fleet.Datastore = redisDS
			if tc.etag {
				ds = etag_invalidate.New(redisDS, nil, logger)
			}
			ledger := ds.(packetfence.LedgerStore)
			policies := ds.(packetfence.PolicyChecker)
			cves := ds.(packetfence.CVEChecker)
			ctx := context.Background()
			_, err := ledger.ListPfRevocationDue(ctx, time.Time{}, 1)
			require.NoError(t, err)
			_, err = ledger.ListPfRevocationGroup(ctx, "mac", "type")
			require.NoError(t, err)
			require.NoError(t, ledger.UpdatePfRevocationFinding(ctx, &fleet.PfRevocationFinding{}))
			cleared, err := ledger.MarkPfGroupClearedFromClearing(ctx, "mac", "type", 1)
			require.NoError(t, err)
			require.True(t, cleared)
			_, err = policies.CheckPfPolicyCompliance(ctx, 1, 2)
			require.NoError(t, err)
			_, err = cves.CheckPfCVECompliance(ctx, 1, "CVE-1", time.Time{})
			require.NoError(t, err)
			assert.Equal(t, []string{"due", "group", "update", "clear", "policy", "cve"}, raw.called)
		})
	}
}

// TestEffectiveRedisConfigETags pins the flag gating: the Redis short
// circuit requires the conditional-request protocol; osquery.config_etags
// off forces it off regardless of osquery.redis_config_etags.
func TestEffectiveRedisConfigETags(t *testing.T) {
	for _, tc := range []struct {
		name        string
		configETags bool
		redisETags  bool
		want        bool
	}{
		{"both enabled", true, true, true},
		{"redis flag off", true, false, false},
		{"protocol off gates redis flag", false, true, false},
		{"both off", false, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.TestConfig()
			cfg.Osquery.ConfigETags = tc.configETags
			cfg.Osquery.RedisConfigETags = tc.redisETags
			assert.Equal(t, tc.want, effectiveRedisConfigETags(cfg))
		})
	}
}

func TestValidateRedisConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cfg     config.RedisConfig
		wantErr bool
		wantSub string
	}{
		{
			name: "host cache disabled with zero ttl is ok",
			cfg:  config.RedisConfig{HostCacheEnabled: false, HostCacheTTL: 0},
		},
		{
			name: "host cache disabled with negative ttl is ok",
			cfg:  config.RedisConfig{HostCacheEnabled: false, HostCacheTTL: -1 * time.Second},
		},
		{
			name: "host cache enabled with positive ttl is ok",
			cfg:  config.RedisConfig{HostCacheEnabled: true, HostCacheTTL: 5 * time.Minute},
		},
		{
			name:    "host cache enabled with zero ttl is rejected",
			cfg:     config.RedisConfig{HostCacheEnabled: true, HostCacheTTL: 0},
			wantErr: true,
			wantSub: "host_cache_ttl must be > 0",
		},
		{
			name:    "host cache enabled with negative ttl is rejected",
			cfg:     config.RedisConfig{HostCacheEnabled: true, HostCacheTTL: -1 * time.Second},
			wantErr: true,
			wantSub: "host_cache_ttl must be > 0",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateRedisConfig(tc.cfg)
			if tc.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.wantSub)
				return
			}
			assert.NoError(t, err)
		})
	}
}

func TestBuildRedisPoolConfigStripsScheme(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "scheme stripped", input: "redis://example.com:6379", want: "example.com:6379"},
		{name: "no scheme passes through", input: "example.com:6379", want: "example.com:6379"},
		{name: "empty passes through", input: "", want: ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := buildRedisPoolConfig(config.RedisConfig{Address: tc.input})
			assert.Equal(t, tc.want, got.Server)
		})
	}
}
