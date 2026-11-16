// Package config reads the collector configuration from environment variables (contract §7).
package config

import (
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/detect"
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
	TileURL           string // WATCHPOST_TILE_URL, served by GET /config.json
	TileOrigin        string // origin of TileURL, allowed in the CSP connect-src

	WazuhIndexerURL      string
	WazuhIndexerUser     string
	WazuhIndexerPassword string
	WazuhIndexerCAFile   string
	WazuhIndexerInsecure bool

	// Remote commands (contract §8).
	CmdKeepAlive time.Duration // WATCHPOST_CMD_KEEPALIVE_S

	// Tracking view (contract §9). AdGuardURL empty: the view is built from net.dns alone.
	AdGuardURL        string
	AdGuardUser       string
	AdGuardPassword   string
	AdGuardLevelsFile string
	AdGuardPoll       time.Duration       // WATCHPOST_ADGUARD_POLL_S
	AdGuardClients    map[string][]string // WATCHPOST_ADGUARD_CLIENTS: device_id -> AdGuard clients (ClientID or IP)

	// Behavioral detections (contract §11.3).
	DetectEnabled  bool              // WATCHPOST_DETECT_ENABLED
	DetectInterval time.Duration     // WATCHPOST_DETECT_INTERVAL_S
	Detect         detect.Thresholds // WATCHPOST_DETECT_* thresholds
}

// DBPath returns the SQLite database path.
func (c *Config) DBPath() string { return filepath.Join(c.DataDir, "watchpost.db") }

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
		Listen:               get("WATCHPOST_LISTEN", ":8080"),
		DataDir:              get("WATCHPOST_DATA_DIR", "/data"),
		ExportPath:           get("WATCHPOST_EXPORT_NDJSON", ""),
		ExportMaxBytes:       intVar("WATCHPOST_EXPORT_MAX_BYTES", 52428800, 1<<20),
		ExportKeep:           int(intVar("WATCHPOST_EXPORT_KEEP", 5, 1)),
		RequireClientCert:    boolVar("WATCHPOST_REQUIRE_CLIENT_CERT", true),
		PublicIngestURL:      get("WATCHPOST_PUBLIC_INGEST_URL", ""),
		PrivateDNSHost:       get("WATCHPOST_PRIVATE_DNS_HOST", ""),
		ServerCAFile:         get("WATCHPOST_SERVER_CA_FILE", ""),
		RetentionDays:        int(intVar("WATCHPOST_RETENTION_DAYS", 90, 1)),
		ConsoleDir:           get("WATCHPOST_CONSOLE_DIR", ""),
		CookieSecure:         boolVar("WATCHPOST_COOKIE_SECURE", true),
		WazuhIndexerURL:      get("WATCHPOST_WAZUH_INDEXER_URL", ""),
		WazuhIndexerUser:     get("WATCHPOST_WAZUH_INDEXER_USER", ""),
		WazuhIndexerPassword: get("WATCHPOST_WAZUH_INDEXER_PASSWORD", ""),
		WazuhIndexerCAFile:   get("WATCHPOST_WAZUH_INDEXER_CA_FILE", ""),
		WazuhIndexerInsecure: boolVar("WATCHPOST_WAZUH_INDEXER_INSECURE", false),
	}
	for _, s := range strings.FieldsFunc(get("WATCHPOST_TRUSTED_PROXIES", "127.0.0.1/32"), splitList) {
		p, err := parsePrefix(s)
		if err != nil {
			errs = append(errs, fmt.Sprintf("WATCHPOST_TRUSTED_PROXIES : %q n'est ni une IP ni un CIDR", s))
			continue
		}
		c.TrustedProxies = append(c.TrustedProxies, p)
	}
	c.TileURL = get("WATCHPOST_TILE_URL", DefaultTileURL)
	if o, err := TileOrigin(c.TileURL); err != nil {
		errs = append(errs, "WATCHPOST_TILE_URL : "+err.Error())
	} else {
		c.TileOrigin = o
	}
	c.CmdKeepAlive = time.Duration(intVar("WATCHPOST_CMD_KEEPALIVE_S", 120, 5)) * time.Second
	if c.CmdKeepAlive > time.Hour {
		errs = append(errs, "WATCHPOST_CMD_KEEPALIVE_S : 3600 au plus")
	}
	c.AdGuardURL = strings.TrimRight(get("WATCHPOST_ADGUARD_URL", ""), "/")
	c.AdGuardUser = get("WATCHPOST_ADGUARD_USER", "")
	c.AdGuardPassword = get("WATCHPOST_ADGUARD_PASSWORD", "")
	c.AdGuardLevelsFile = get("WATCHPOST_ADGUARD_LEVELS_FILE", "")
	c.AdGuardPoll = time.Duration(intVar("WATCHPOST_ADGUARD_POLL_S", 60, 10)) * time.Second
	if c.AdGuardURL != "" {
		if err := CheckAdGuardURL(c.AdGuardURL); err != nil {
			errs = append(errs, "WATCHPOST_ADGUARD_URL : "+err.Error())
		}
	}
	if clients, err := parseClients(get("WATCHPOST_ADGUARD_CLIENTS", "")); err != nil {
		errs = append(errs, "WATCHPOST_ADGUARD_CLIENTS : "+err.Error())
	} else {
		c.AdGuardClients = clients
	}
	c.DetectEnabled = boolVar("WATCHPOST_DETECT_ENABLED", true)
	c.DetectInterval = time.Duration(intVar("WATCHPOST_DETECT_INTERVAL_S", 300, 10)) * time.Second
	if c.DetectInterval > 24*time.Hour {
		errs = append(errs, "WATCHPOST_DETECT_INTERVAL_S : 86400 au plus")
	}
	th, derrs := detect.ParseEnv(func(k string) string { return get(k, "") })
	c.Detect = th
	errs = append(errs, derrs...)
	if len(errs) > 0 {
		return nil, fmt.Errorf("configuration invalide : %s", strings.Join(errs, " ; "))
	}
	return c, nil
}

// DefaultTileURL is the default map tile template (contract §6).
const DefaultTileURL = "https://tile.openstreetmap.org/{z}/{x}/{y}.png"

// TileOrigin derives the CSP origin of a tile URL template such as
// "https://{s}.tile.example.org/{z}/{x}/{y}.png" (a "{s}" host label becomes "*").
func TileOrigin(tileURL string) (string, error) {
	if len(tileURL) > 512 || strings.ContainsAny(tileURL, " \t\r\n;,'\"") {
		return "", fmt.Errorf("%q : URL invalide", tileURL)
	}
	rest, ok := strings.CutPrefix(tileURL, "https://")
	if !ok {
		return "", fmt.Errorf("%q : URL https:// attendue", tileURL)
	}
	host := rest
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		host = rest[:i]
	}
	labels := strings.Split(host, ".")
	for i, l := range labels {
		if strings.HasPrefix(l, "{") && strings.HasSuffix(l, "}") && i == 0 {
			labels[i] = "*"
		}
	}
	origin := "https://" + strings.Join(labels, ".")
	if !validOrigin(origin) || strings.Contains(origin[len("https://"):], "*") && !strings.HasPrefix(origin, "https://*.") {
		return "", fmt.Errorf("%q : hôte invalide", tileURL)
	}
	return origin, nil
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

// CheckAdGuardURL accepts an absolute http(s) URL without credentials, query or fragment: the address of
// the AdGuard Home administration API comes from the configuration only, never from a request.
func CheckAdGuardURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%q : URL http(s)://hôte[:port] attendue", raw)
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return fmt.Errorf("URL sans identifiants, requête ni fragment attendue (identifiants : WATCHPOST_ADGUARD_USER et WATCHPOST_ADGUARD_PASSWORD)")
	}
	return nil
}

var clientRe = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
var deviceRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// parseClients reads "dev_a=client1,dev_a=client2,dev_b=client3".
func parseClients(v string) (map[string][]string, error) {
	out := map[string][]string{}
	for _, part := range strings.FieldsFunc(v, splitList) {
		dev, cl, ok := strings.Cut(part, "=")
		if !ok || !deviceRe.MatchString(dev) || !clientRe.MatchString(cl) {
			return nil, fmt.Errorf("%q : paires device_id=client (ClientID ou IP AdGuard) attendues", part)
		}
		out[dev] = append(out[dev], cl)
	}
	return out, nil
}
