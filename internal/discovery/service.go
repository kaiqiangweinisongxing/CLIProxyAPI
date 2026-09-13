package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
)

// ResolveDiscoveryStateDir returns an absolute state directory for discovery metadata,
// avoiding writing relative paths into the current working directory.
func ResolveDiscoveryStateDir() string {
	if writable := util.WritablePath(); writable != "" {
		return filepath.Join(writable, "discovery")
	}
	if configDir, err := os.UserConfigDir(); err == nil && configDir != "" {
		return filepath.Join(configDir, "cpa", "discovery")
	}
	if homeDir, err := os.UserHomeDir(); err == nil && homeDir != "" {
		return filepath.Join(homeDir, ".config", "cpa", "discovery")
	}
	return ""
}

// validateServiceType checks whether st conforms to RFC 6763 / RFC 6335 service type format.
// Expected format: "_<name>._tcp" or "_<name>._udp" (e.g. "_ai-gateway._tcp").
func validateServiceType(st string) error {
	st = strings.TrimSpace(st)
	if st == "" {
		return fmt.Errorf("service type cannot be empty")
	}
	if len(st) > 63 {
		return fmt.Errorf("service type %q exceeds 63 characters", st)
	}
	if !strings.HasSuffix(st, "._tcp") && !strings.HasSuffix(st, "._udp") {
		return fmt.Errorf("service type %q must end with ._tcp or ._udp", st)
	}
	prefix := st[:len(st)-5]
	if !strings.HasPrefix(prefix, "_") {
		return fmt.Errorf("service type %q must start with an underscore", st)
	}
	name := prefix[1:]
	if len(name) == 0 || len(name) > 15 {
		return fmt.Errorf("service name %q must be between 1 and 15 characters (RFC 6335)", name)
	}
	for i, r := range name {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-') {
			return fmt.Errorf("service type contains invalid character %q (RFC 6335)", r)
		}
		if (i == 0 || i == len(name)-1) && r == '-' {
			return fmt.Errorf("service name cannot start or end with a hyphen")
		}
	}
	return nil
}

// sanitizeSubtype ensures subtype is a valid DNS-SD label prefixed with '_'.
func sanitizeSubtype(sub string) string {
	sub = strings.TrimSpace(sub)
	if sub == "" {
		return ""
	}
	if idx := strings.Index(sub, "._sub"); idx != -1 {
		sub = sub[:idx]
	}
	if !strings.HasPrefix(sub, "_") {
		sub = "_" + sub
	}
	label := sub[1:]
	if len(label) == 0 || len(label) > 63 {
		return ""
	}
	for _, r := range label {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_') {
			return ""
		}
	}
	return sub
}

// sanitizeInstanceName limits name to 63 bytes and removes control characters.
func sanitizeInstanceName(name string) string {
	var b strings.Builder
	for _, r := range name {
		if r >= 32 && r != 127 {
			b.WriteRune(r)
		}
	}
	res := strings.TrimSpace(b.String())
	if len(res) > 63 {
		res = res[:63]
	}
	return res
}

// BuildServiceSpec creates a ServiceSpec from configuration, port, and TLS setting.
func BuildServiceSpec(cfg *config.Config, port int, tlsEnabled bool) (ServiceSpec, error) {
	if cfg == nil {
		return ServiceSpec{}, fmt.Errorf("discovery: config is nil")
	}
	discCfg := cfg.Discovery

	// 1. Resolve State Dir for persistent instance ID
	stateDir := ResolveDiscoveryStateDir()
	instanceID := GetOrGenerateInstanceID(stateDir)

	// 2. Format instance name (CPA-<4-char-hex> default) with length/char sanitization
	instanceName := sanitizeInstanceName(FormatInstanceName(discCfg.ServiceName, instanceID))
	if instanceName == "" {
		instanceName = "CPA-" + instanceID
	}

	// 3. Service type validation (RFC 6763 / RFC 6335)
	serviceType := strings.TrimSpace(discCfg.ServiceType)
	if serviceType == "" {
		serviceType = DefaultServiceType
	} else if errST := validateServiceType(serviceType); errST != nil {
		return ServiceSpec{}, fmt.Errorf("discovery: invalid service-type: %w", errST)
	}

	// 4. Subtypes sanitization
	var subtypes []string
	rawSubtypes := discCfg.Subtypes
	if len(rawSubtypes) == 0 {
		rawSubtypes = []string{SubtypeCliproxy, SubtypeOpenAI, SubtypeAnthropic}
	}
	for _, raw := range rawSubtypes {
		if clean := sanitizeSubtype(raw); clean != "" {
			subtypes = append(subtypes, clean)
		}
	}
	if len(subtypes) == 0 {
		subtypes = []string{SubtypeCliproxy}
	}

	// 5. Interface filtering (Scheme C)
	ifaces, err := FilterInterfaces(discCfg.Interfaces.Include, discCfg.Interfaces.Exclude)
	if err != nil {
		log.Warnf("discovery: failed to filter interfaces: %v", err)
	}
	if len(ifaces) == 0 {
		return ServiceSpec{}, fmt.Errorf("discovery: no qualified physical interfaces found matching filters (refusing fallback to all interfaces)")
	}

	// 6. Build TXT records
	txtOpts := DefaultTXTOptions()
	txtOpts.InstanceID = instanceID
	txtOpts.TLS = tlsEnabled
	txtOpts.AdvertiseManagement = discCfg.AdvertiseManagement
	if discCfg.AuthRequired != nil {
		txtOpts.AuthRequired = *discCfg.AuthRequired
	} else {
		txtOpts.AuthRequired = true
	}

	txtRecords := BuildTXTRecords(txtOpts)

	return ServiceSpec{
		InstanceName: instanceName,
		ServiceType:  serviceType,
		Domain:       DefaultDomain,
		Port:         port,
		Subtypes:     subtypes,
		LegacyAlias:  discCfg.LegacyAlias,
		TextRecords:  txtRecords,
		Interfaces:   ifaces,
	}, nil
}
