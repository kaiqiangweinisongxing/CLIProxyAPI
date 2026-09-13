package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/grandcat/zeroconf"
	log "github.com/sirupsen/logrus"
)

// ZeroconfAdvertiser wraps grandcat/zeroconf.Server with defensive lifecycle management.
type ZeroconfAdvertiser struct {
	mu       sync.Mutex
	servers  []*zeroconf.Server
	closed   bool
	stopOnce sync.Once
	stopCh   chan struct{}
}

// NewZeroconfAdvertiser returns a new ZeroconfAdvertiser.
func NewZeroconfAdvertiser() *ZeroconfAdvertiser {
	return &ZeroconfAdvertiser{}
}

// extractCleanHost returns bare hostname without any .local suffix
// to prevent grandcat/zeroconf from appending a duplicate .local. (e.g. on macOS).
func extractCleanHost() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "localhost"
	}
	h = strings.TrimSpace(h)
	h = strings.TrimSuffix(h, ".")
	h = strings.TrimSuffix(h, ".local")
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "localhost"
	}
	return h
}

// extractInterfaceIPs collects non-loopback IP addresses from the selected interfaces.
func extractInterfaceIPs(ifaces []net.Interface) []string {
	var ips []string
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			ips = append(ips, ip.String())
		}
	}
	return ips
}

// Start registers and starts mDNS advertisement for the primary service type
// and any configured aliases/subtypes.
func (a *ZeroconfAdvertiser) Start(ctx context.Context, spec ServiceSpec) (err error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.servers) > 0 {
		return fmt.Errorf("discovery: advertiser already started")
	}

	if len(spec.Interfaces) == 0 {
		return fmt.Errorf("discovery: cannot start advertiser with empty interface list (refusing fallback to all interfaces)")
	}

	a.stopCh = make(chan struct{})
	a.stopOnce = sync.Once{}

	// Defensive: Panic recovery and error rollback
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("discovery: panic starting advertiser: %v", r)
			log.Errorf("%v", err)
		}
		if err != nil {
			for _, s := range a.servers {
				if s != nil {
					s.Shutdown()
				}
			}
			a.servers = nil
			a.stopOnce.Do(func() {
				if a.stopCh != nil {
					close(a.stopCh)
				}
			})
		}
	}()

	domain := spec.Domain
	if domain == "" {
		domain = DefaultDomain
	}
	serviceType := spec.ServiceType
	if serviceType == "" {
		serviceType = DefaultServiceType
	}

	cleanHost := extractCleanHost()
	ips := extractInterfaceIPs(spec.Interfaces)
	if len(ips) == 0 {
		return fmt.Errorf("discovery: no qualified IP addresses found on specified interfaces")
	}

	// 1. Primary advertisement: e.g. _ai-gateway._tcp
	primaryServer, errRegister := zeroconf.RegisterProxy(
		spec.InstanceName,
		serviceType,
		domain,
		spec.Port,
		cleanHost,
		ips,
		spec.TextRecords,
		spec.Interfaces,
	)
	if errRegister != nil {
		return fmt.Errorf("discovery: failed to register primary service %s: %w", serviceType, errRegister)
	}
	a.servers = append(a.servers, primaryServer)

	// 2. Subtype / Alias registration if requested
	for _, sub := range spec.Subtypes {
		sub = strings.TrimSpace(sub)
		if sub == "" {
			continue
		}
		// Register subtype PTR or alias: e.g. _cliproxy._sub._ai-gateway._tcp
		subTypeStr := fmt.Sprintf("%s._sub.%s", sub, serviceType)
		subServer, errSub := zeroconf.RegisterProxy(
			spec.InstanceName,
			subTypeStr,
			domain,
			spec.Port,
			cleanHost,
			ips,
			spec.TextRecords,
			spec.Interfaces,
		)
		if errSub == nil {
			a.servers = append(a.servers, subServer)
		} else {
			log.Debugf("discovery: optional subtype registration for %s skipped: %v", subTypeStr, errSub)
		}
	}

	// 3. Legacy compatibility alias registration (_cliproxy._tcp) if requested
	if spec.LegacyAlias && spec.ServiceType != "_cliproxy._tcp" {
		aliasServer, errAlias := zeroconf.RegisterProxy(
			spec.InstanceName,
			"_cliproxy._tcp",
			domain,
			spec.Port,
			cleanHost,
			ips,
			spec.TextRecords,
			spec.Interfaces,
		)
		if errAlias == nil {
			a.servers = append(a.servers, aliasServer)
		} else {
			log.Debugf("discovery: legacy alias registration for _cliproxy._tcp skipped: %v", errAlias)
		}
	}

	a.closed = false
	return nil
}

// Stop shuts down all mDNS advertisement servers and sends goodbye packets.
func (a *ZeroconfAdvertiser) Stop() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	a.stopOnce.Do(func() {
		if a.stopCh != nil {
			close(a.stopCh)
		}
	})

	if len(a.servers) == 0 || a.closed {
		return nil
	}

	a.closed = true
	defer func() {
		if r := recover(); r != nil {
			log.Warnf("discovery: panic during advertiser shutdown: %v", r)
		}
	}()

	for _, s := range a.servers {
		if s != nil {
			s.Shutdown()
		}
	}
	a.servers = nil
	return nil
}

// ZeroconfBrowser provides DNS-SD browsing with fallback support.
type ZeroconfBrowser struct {
	options []zeroconf.ClientOption
}

// NewZeroconfBrowser creates a new ZeroconfBrowser.
func NewZeroconfBrowser(ifaces ...net.Interface) *ZeroconfBrowser {
	var opts []zeroconf.ClientOption
	if len(ifaces) > 0 {
		opts = append(opts, zeroconf.SelectIfaces(ifaces))
	}
	return &ZeroconfBrowser{options: opts}
}

// Browse performs a standard mDNS browse query for the given service type.
func (b *ZeroconfBrowser) Browse(ctx context.Context, serviceType, domain string, timeout time.Duration) ([]DiscoveredService, error) {
	if domain == "" {
		domain = DefaultDomain
	}
	if serviceType == "" {
		serviceType = DefaultServiceType
	}

	resolver, err := zeroconf.NewResolver(b.options...)
	if err != nil {
		return nil, fmt.Errorf("discovery: failed to initialize resolver: %w", err)
	}

	ctxTimeout, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	entries := make(chan *zeroconf.ServiceEntry, 32)
	var discovered []DiscoveredService
	var mu sync.Mutex
	seen := make(map[string]bool)

	// Collect entries in background until channel is closed by zeroconf's params.done()
	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		for entry := range entries {
			if entry == nil {
				continue
			}
			svc := entryToDiscovered(entry)
			key := fmt.Sprintf("%s:%s:%d", svc.InstanceName, svc.Host, svc.Port)
			mu.Lock()
			if !seen[key] {
				seen[key] = true
				discovered = append(discovered, svc)
			}
			mu.Unlock()
		}
	}()

	errBrowse := resolver.Browse(ctxTimeout, serviceType, domain, entries)
	if errBrowse != nil {
		cancel() // Signal resolver to terminate
		<-doneCh // Wait for entries channel to be closed by resolver
		return nil, fmt.Errorf("discovery: browse query failed: %w", errBrowse)
	}

	<-ctxTimeout.Done()
	<-doneCh

	return discovered, nil
}

// BrowseWithFallback discovers all AI gateways on the LAN (_ai-gateway._tcp) and prioritizes CPA instances.
// If no gateways are found, it falls back to checking for legacy CPA instances advertising _cliproxy._tcp.
func (b *ZeroconfBrowser) BrowseWithFallback(ctx context.Context, timeout time.Duration) ([]DiscoveredService, error) {
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// 1. Primary discovery: scan for all AI gateways on the LAN
	allGateways, errMain := b.Browse(ctx, DefaultServiceType, DefaultDomain, timeout)
	if errMain != nil && len(allGateways) == 0 {
		return nil, errMain
	}

	// 2. If nothing found on primary service type, try legacy CPA alias _cliproxy._tcp
	if len(allGateways) == 0 {
		legacyTimeout := 1 * time.Second
		if timeout < legacyTimeout {
			legacyTimeout = timeout
		}
		legacyGateways, errLegacy := b.Browse(ctx, "_cliproxy._tcp", DefaultDomain, legacyTimeout)
		if errLegacy == nil && len(legacyGateways) > 0 {
			allGateways = legacyGateways
		}
	}

	// 3. Partition: prioritize CPA instances first, then other standard AI gateways
	var cpaGateways []DiscoveredService
	var otherGateways []DiscoveredService
	for _, gw := range allGateways {
		if gw.Product == ProductCPA || strings.Contains(gw.ServiceType, "_cliproxy") {
			cpaGateways = append(cpaGateways, gw)
		} else {
			otherGateways = append(otherGateways, gw)
		}
	}

	return append(cpaGateways, otherGateways...), nil
}

// sanitizeEndpointPath validates that an endpoint path is a safe relative API path
// starting with '/' and containing no scheme, domain, or traversal elements.
func sanitizeEndpointPath(p string) string {
	p = strings.TrimSpace(p)
	if !strings.HasPrefix(p, "/") || strings.Contains(p, "://") || strings.Contains(p, "..") {
		return ""
	}
	for _, r := range p {
		if r < 32 || r == 127 {
			return ""
		}
	}
	return p
}

func entryToDiscovered(e *zeroconf.ServiceEntry) DiscoveredService {
	parsed := ParseTXTRecords(e.Text)

	port := e.Port
	if port < 1 || port > 65535 {
		port = 0
	}

	svc := DiscoveredService{
		InstanceName: e.Instance,
		ServiceType:  e.Service,
		Domain:       e.Domain,
		Host:         e.HostName,
		Port:         port,
		IPv4:         e.AddrIPv4,
		IPv6:         e.AddrIPv6,
		Product:      parsed["product"],
		Version:      parsed["version"],
		NodeRole:     parsed["node_role"],
		RawTXT:       parsed,
		Endpoints:    make(map[string]string),
	}

	if parsed["auth_required"] == "true" {
		svc.AuthRequired = true
	}
	if methods := parsed["auth_methods"]; methods != "" {
		svc.AuthMethods = strings.Split(methods, ",")
	}
	if protos := parsed["protocols"]; protos != "" {
		svc.Protocols = strings.Split(protos, ",")
	}
	if feats := parsed["features"]; feats != "" {
		svc.Features = strings.Split(feats, ",")
	}

	if v, ok := parsed["api_openai"]; ok {
		if clean := sanitizeEndpointPath(v); clean != "" {
			svc.Endpoints["openai"] = clean
		}
	}
	if v, ok := parsed["api_anthropic"]; ok {
		if clean := sanitizeEndpointPath(v); clean != "" {
			svc.Endpoints["anthropic"] = clean
		}
	}
	if v, ok := parsed["api_gemini"]; ok {
		if clean := sanitizeEndpointPath(v); clean != "" {
			svc.Endpoints["gemini"] = clean
		}
	}

	return svc
}
