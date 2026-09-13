package cliproxy

import (
	"context"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/discovery"
	log "github.com/sirupsen/logrus"
)

type discoveryAdvertiserManager struct {
	mu         sync.Mutex
	advertiser discovery.Advertiser
	enabled    bool
	lastSpec   discovery.ServiceSpec
}

func newDiscoveryAdvertiserManager() *discoveryAdvertiserManager {
	return &discoveryAdvertiserManager{}
}

func (s *Service) applyDiscoveryConfig(cfg *config.Config) {
	s.applyDiscoveryConfigContext(context.Background(), cfg)
}

func (s *Service) applyDiscoveryConfigContext(ctx context.Context, cfg *config.Config) bool {
	if s == nil || cfg == nil || (ctx != nil && ctx.Err() != nil) {
		return false
	}
	if s.discoveryManager == nil {
		s.discoveryManager = newDiscoveryAdvertiserManager()
	}
	return s.discoveryManager.ApplyContext(ctx, cfg, cfg.Port, cfg.TLS.Enable)
}

func (s *Service) shutdownDiscovery() error {
	if s == nil || s.discoveryManager == nil {
		return nil
	}
	return s.discoveryManager.Shutdown()
}

func (m *discoveryAdvertiserManager) ApplyContext(ctx context.Context, cfg *config.Config, port int, tlsEnabled bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !cfg.Discovery.Enabled {
		if m.advertiser != nil {
			log.Info("discovery: stopping mDNS advertisement (disabled by config)")
			_ = m.advertiser.Stop()
			m.advertiser = nil
			m.enabled = false
		}
		return true
	}

	spec, err := discovery.BuildServiceSpec(cfg, port, tlsEnabled)
	if err != nil {
		log.Warnf("discovery: failed to build service spec: %v", err)
		return false
	}

	// Idempotence check: if already running and spec is unchanged, skip restart
	if m.enabled && m.advertiser != nil && specEqual(m.lastSpec, spec) {
		return true
	}

	// If already enabled and running, restart with new spec on reload
	if m.advertiser != nil {
		_ = m.advertiser.Stop()
		m.advertiser = nil
	}

	adv := discovery.NewZeroconfAdvertiser()
	if errStart := adv.Start(ctx, spec); errStart != nil {
		log.Warnf("discovery: failed to start mDNS advertiser: %v (degraded, HTTP intact)", errStart)
		return false
	}

	m.advertiser = adv
	m.enabled = true
	m.lastSpec = spec
	log.Infof("discovery: advertising as '%s.%s' on port %d", spec.InstanceName, spec.ServiceType, port)
	return true
}

func (m *discoveryAdvertiserManager) Shutdown() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.lastSpec = discovery.ServiceSpec{}
	if m.advertiser != nil {
		err := m.advertiser.Stop()
		m.advertiser = nil
		m.enabled = false
		return err
	}
	return nil
}

func specEqual(a, b discovery.ServiceSpec) bool {
	if a.InstanceName != b.InstanceName ||
		a.ServiceType != b.ServiceType ||
		a.Domain != b.Domain ||
		a.Port != b.Port ||
		a.LegacyAlias != b.LegacyAlias ||
		len(a.Subtypes) != len(b.Subtypes) ||
		len(a.TextRecords) != len(b.TextRecords) ||
		len(a.Interfaces) != len(b.Interfaces) {
		return false
	}
	for i := range a.Subtypes {
		if a.Subtypes[i] != b.Subtypes[i] {
			return false
		}
	}
	for i := range a.TextRecords {
		if a.TextRecords[i] != b.TextRecords[i] {
			return false
		}
	}
	for i := range a.Interfaces {
		if a.Interfaces[i].Name != b.Interfaces[i].Name {
			return false
		}
	}
	return true
}
