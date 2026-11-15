// Package config reads the collector configuration from environment variables (contract §7).
package config

import (
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Config is the collector configuration.
type Config struct {
	Listen            string
	DataDir           string
	ExportPath        string
	ExportMaxBytes    int64
	ExportKeep        int
	TrustedProxies    []netip.Prefix
	RequireClientCert bool
	PublicIngestURL   string
	PrivateDNSHost    string
	ServerCAFile      string
	RetentionDays     int
	ConsoleDir        string
	CookieSecure      bool
	MapTileOrigins    []string

	WazuhIndexerURL      string
	WazuhIndexerUser     string
	WazuhIndexerPassword string
	WazuhIndexerCAFile   string
	WazuhIndexerInsecure bool
}

// DBPath returns the SQLite database path.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "vigie.db") }

// PKIDir returns the client PKI directory.
func (c *Config) PKIDir() string { return filepath.Join(c.DataDir, "pki") }

// FromEnv builds the configuration from the process environment.
func FromEnv() (*Config, error) { return FromLookup(os.LookupEnv) }

// FromLookup builds the configuration using the given lookup function.
func FromLookup(lookup func(string) (string, bool)) (*Config, error) {
	get := func(k, def string) string {
		if v, ok := lookup(k); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		return def
	}
	var errs []string
	boolVar := func(k string, def bool) bool {
		v := get(k, "")
		if v == "" {
			return def
		}
		b, err := strconv.ParseBool(v)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s : booléen attendu", k))
			return def
		}
		return b
	}
	intVar := func(k string, def int64, min int64) int64 {
		v := get(k, "")
		if v == "" {
			return def
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < min {
			errs = append(errs, fmt.Sprintf("%s : entier >= %d attendu", k, min))
			return def
		}
		return n
	}

	c := &Config{
		Listen:               get("VIGIE_LISTEN", ":8080"),
		DataDir:              get("VIGIE_DATA_DIR", "/data"),
		ExportPath:           get("VIGIE_EXPORT_NDJSON", ""),
		ExportMaxBytes:       intVar("VIGIE_EXPORT_MAX_BYTES", 52428800, 1<<20),
		ExportKeep:           int(intVar("VIGIE_EXPORT_KEEP", 5, 1)),
		RequireClientCert:    boolVar("VIGIE_REQUIRE_CLIENT_CERT", true),
		PublicIngestURL:      get("VIGIE_PUBLIC_INGEST_URL", ""),
		PrivateDNSHost:       get("VIGIE_PRIVATE_DNS_HOST", ""),
		ServerCAFile:         get("VIGIE_SERVER_CA_FILE", ""),
		RetentionDays:        int(intVar("VIGIE_RETENTION_DAYS", 90, 1)),
		ConsoleDir:           get("VIGIE_CONSOLE_DIR", ""),
		CookieSecure:         boolVar("VIGIE_COOKIE_SECURE", true),
		WazuhIndexerURL:      get("VIGIE_WAZUH_INDEXER_URL", ""),
		WazuhIndexerUser:     get("VIGIE_WAZUH_INDEXER_USER", ""),
		WazuhIndexerPassword: get("VIGIE_WAZUH_INDEXER_PASSWORD", ""),
		WazuhIndexerCAFile:   get("VIGIE_WAZUH_INDEXER_CA_FILE", ""),
		WazuhIndexerInsecure: boolVar("VIGIE_WAZUH_INDEXER_INSECURE", false),
	}
	for _, s := range strings.FieldsFunc(get("VIGIE_TRUSTED_PROXIES", "127.0.0.1/32"), splitList) {
		p, err := parsePrefix(s)
		if err != nil {
			errs = append(errs, fmt.Sprintf("VIGIE_TRUSTED_PROXIES : %q n'est ni une IP ni un CIDR", s))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}
	for _, s := range strings.FieldsFunc(get("VIGIE_MAP_TILE_ORIGINS", "https://tile.openstreetmap.org"), splitList) {
		if !validOrigin(s) {
			errs = append(errs, fmt.Sprintf("VIGIE_MAP_TILE_ORIGINS : %q n'est pas une origine https://hôte[:port]", s))
			continue
		}
		c.MapTileOrigins = append(c.MapTileOrigins, s)
	}
	if len(errs) > 0 {
		return nil, fmt.Errorf("configuration invalide : %s", strings.Join(errs, " ; "))
	}
	return c, nil
}

func splitList(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }

func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return p, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// validOrigin accepts "https://host[:port]" with a conservative character set,
// because the value is copied into the Content-Security-Policy header.
func validOrigin(s string) bool {
	rest, ok := strings.CutPrefix(s, "https://")
	if !ok || rest == "" || len(rest) > 253 {
		return false
	}
	for _, r := range rest {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == ':', r == '*':
		default:
			return false
		}
	}
	return true
}
