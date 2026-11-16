// Package detect computes the behavioral detections of contract §11.3 from the aggregates already stored
// by the collector: one pure function per detection (rules.go), fed and run periodically by Engine.
package detect

import (
	"bufio"
	_ "embed"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Detection types (contract §11.3), produced as events of the collector (source "server").
const (
	TypeThreatDomain     = "detect.threat_domain"
	TypeUploadSpike      = "detect.upload_spike"
	TypeFanout           = "detect.fanout"
	TypeMailPorts        = "detect.mail_ports"
	TypeDNSBypass        = "detect.dns_bypass"
	TypeSMSAbuse         = "detect.sms_abuse"
	TypeSensorBackground = "detect.sensor_background"
	TypeNewAppRisky      = "detect.new_app_risky"
	// Contract §11.4: detections that work without app.ops.
	TypeSMSPermission     = "detect.sms_permission"
	TypeDefaultAppChanged = "detect.default_app_changed"
	// An inventory that declares "system" an application its installer or its history show was installed
	// (contract §11.4).
	TypeInventoryMismatch = "detect.inventory_mismatch"
)

// Types lists the detection types.
var Types = []string{TypeThreatDomain, TypeUploadSpike, TypeFanout, TypeMailPorts, TypeDNSBypass, TypeSMSAbuse,
	TypeSensorBackground, TypeNewAppRisky, TypeSMSPermission, TypeDefaultAppChanged, TypeInventoryMismatch}

// Fixed parameters (contract or definition of the detections, not thresholds).
const (
	UploadHistory       = 14 * 24 * time.Hour // window of the hourly median (contract)
	UploadMinActiveHrs  = 24                  // hours with traffic needed for an application's median
	NewAppWindow        = 24 * time.Hour      // "installed less than 24 h ago" (contract)
	ScreenOffMaxMinutes = 5                   // an hour with the screen on 5 min at most counts as "screen off"
)

// Thresholds are the tunable parameters of the detections (WATCHPOST_DETECT_* variables, see the README for
// the reasoning behind each default).
type Thresholds struct {
	Disabled map[string]bool // detection types turned off

	UploadFloorBytes int64   // WATCHPOST_DETECT_UPLOAD_FLOOR_MB (MiB): absolute floor of an hour's upload
	UploadFactor     float64 // WATCHPOST_DETECT_UPLOAD_FACTOR: k of k × median
	UploadLearnDays  int     // WATCHPOST_DETECT_UPLOAD_LEARN_DAYS: device history needed before the median is used

	Fanout          int // WATCHPOST_DETECT_FANOUT: distinct addresses per application and hour
	FanoutScreenOff int // WATCHPOST_DETECT_FANOUT_SCREEN_OFF: same, for an hour spent screen off

	MailMin     int             // WATCHPOST_DETECT_MAIL_MIN: connections per day to ports 25/465/587
	MailClients map[string]bool // mail_clients.txt + WATCHPOST_DETECT_MAIL_CLIENTS

	DNSBypassMin    int             // WATCHPOST_DETECT_DNS_BYPASS_MIN: connections per day to a known public resolver
	DNSBypassPorts  map[int]bool    // WATCHPOST_DETECT_DNS_BYPASS_PORTS
	DNSBypassExempt map[string]bool // WATCHPOST_DETECT_DNS_BYPASS_EXEMPT

	SMSOtherMin int64 // WATCHPOST_DETECT_SMS_OTHER_MIN: SMS per day sent by an app that is not the SMS app
	SMSDailyMax int64 // WATCHPOST_DETECT_SMS_DAILY_MAX: SMS per day of any app above which it is reported

	MicBackgroundMin    int64 // WATCHPOST_DETECT_MIC_BG_MIN: background uses of the microphone per day
	CameraBackgroundMin int64 // WATCHPOST_DETECT_CAMERA_BG_MIN: background uses of the camera per day
}

// Defaults returns the default thresholds.
func Defaults() Thresholds {
	return Thresholds{
		Disabled:         map[string]bool{},
		UploadFloorBytes: 1024 << 20, UploadFactor: 10, UploadLearnDays: 7,
		Fanout: 300, FanoutScreenOff: 100,
		MailMin: 1, MailClients: defaultMailClients(),
		DNSBypassMin: 1, DNSBypassPorts: map[int]bool{443: true, 853: true}, DNSBypassExempt: map[string]bool{},
		SMSOtherMin: 1, SMSDailyMax: 200,
		MicBackgroundMin: 10, CameraBackgroundMin: 3,
	}
}

// Enabled reports whether a detection type is on.
func (t Thresholds) Enabled(typ string) bool { return !t.Disabled[typ] }

//go:embed mail_clients.txt
var mailClientsTxt string

func defaultMailClients() map[string]bool {
	out := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(mailClientsTxt))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			out[line] = true
		}
	}
	return out
}

var packageRe = regexp.MustCompile(`^[A-Za-z0-9_.]{1,255}$`)

func splitList(v string) []string {
	return strings.FieldsFunc(v, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' })
}

// ParseEnv reads the WATCHPOST_DETECT_* variables (get returns "" when unset) on top of the defaults. It
// returns the thresholds and the list of errors (empty when valid).
func ParseEnv(get func(string) string) (Thresholds, []string) {
	t := Defaults()
	var errs []string
	intVar := func(k string, def, min, max int64) int64 {
		v := get(k)
		if v == "" {
			return def
		}
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < min || n > max {
			errs = append(errs, fmt.Sprintf("%s: integer between %d and %d expected", k, min, max))
			return def
		}
		return n
	}
	for _, name := range splitList(get("WATCHPOST_DETECT_DISABLE")) {
		typ := name
		if !strings.HasPrefix(typ, "detect.") {
			typ = "detect." + typ
		}
		known := false
		for _, x := range Types {
			known = known || x == typ
		}
		if !known {
			errs = append(errs, fmt.Sprintf("WATCHPOST_DETECT_DISABLE: unknown detection %q", name))
			continue
		}
		t.Disabled[typ] = true
	}
	t.UploadFloorBytes = intVar("WATCHPOST_DETECT_UPLOAD_FLOOR_MB", t.UploadFloorBytes>>20, 1, 1<<20) << 20
	if v := get("WATCHPOST_DETECT_UPLOAD_FACTOR"); v != "" {
		f, err := strconv.ParseFloat(v, 64)
		if err != nil || f < 1 || f > 1000 {
			errs = append(errs, "WATCHPOST_DETECT_UPLOAD_FACTOR: number between 1 and 1000 expected")
		} else {
			t.UploadFactor = f
		}
	}
	t.UploadLearnDays = int(intVar("WATCHPOST_DETECT_UPLOAD_LEARN_DAYS", int64(t.UploadLearnDays), 0, 14))
	t.Fanout = int(intVar("WATCHPOST_DETECT_FANOUT", int64(t.Fanout), 2, 1000000))
	t.FanoutScreenOff = int(intVar("WATCHPOST_DETECT_FANOUT_SCREEN_OFF", int64(t.FanoutScreenOff), 2, 1000000))
	t.MailMin = int(intVar("WATCHPOST_DETECT_MAIL_MIN", int64(t.MailMin), 1, 1000000))
	for _, p := range splitList(get("WATCHPOST_DETECT_MAIL_CLIENTS")) {
		if !packageRe.MatchString(p) {
			errs = append(errs, fmt.Sprintf("WATCHPOST_DETECT_MAIL_CLIENTS: %q is not a package name", p))
			continue
		}
		t.MailClients[p] = true
	}
	t.DNSBypassMin = int(intVar("WATCHPOST_DETECT_DNS_BYPASS_MIN", int64(t.DNSBypassMin), 1, 1000000))
	if v := get("WATCHPOST_DETECT_DNS_BYPASS_PORTS"); v != "" {
		ports := map[int]bool{}
		for _, p := range splitList(v) {
			n, err := strconv.Atoi(p)
			if err != nil || n < 1 || n > 65535 {
				errs = append(errs, fmt.Sprintf("WATCHPOST_DETECT_DNS_BYPASS_PORTS: invalid port %q", p))
				continue
			}
			ports[n] = true
		}
		t.DNSBypassPorts = ports
	}
	for _, p := range splitList(get("WATCHPOST_DETECT_DNS_BYPASS_EXEMPT")) {
		if !packageRe.MatchString(p) {
			errs = append(errs, fmt.Sprintf("WATCHPOST_DETECT_DNS_BYPASS_EXEMPT: %q is not a package name", p))
			continue
		}
		t.DNSBypassExempt[p] = true
	}
	t.SMSOtherMin = intVar("WATCHPOST_DETECT_SMS_OTHER_MIN", t.SMSOtherMin, 1, 1000000)
	t.SMSDailyMax = intVar("WATCHPOST_DETECT_SMS_DAILY_MAX", t.SMSDailyMax, 1, 1000000)
	t.MicBackgroundMin = intVar("WATCHPOST_DETECT_MIC_BG_MIN", t.MicBackgroundMin, 1, 1000000)
	t.CameraBackgroundMin = intVar("WATCHPOST_DETECT_CAMERA_BG_MIN", t.CameraBackgroundMin, 1, 1000000)
	return t, errs
}

// Resolvers is the list of known public DNS resolvers (resolvers.txt).
type Resolvers struct {
	addrs    map[netip.Addr]string
	prefixes []resolverPrefix
}

type resolverPrefix struct {
	p    netip.Prefix
	name string
}

//go:embed resolvers.txt
var resolversTxt string

// DefaultResolvers returns the embedded list of known public resolvers.
func DefaultResolvers() *Resolvers {
	r, err := ParseResolvers(resolversTxt)
	if err != nil {
		panic(err) // embedded file, checked by the tests
	}
	return r
}

// ParseResolvers reads "address-or-CIDR name" lines ("#" starts a comment).
func ParseResolvers(txt string) (*Resolvers, error) {
	r := &Resolvers{addrs: map[netip.Addr]string{}}
	sc := bufio.NewScanner(strings.NewReader(txt))
	n := 0
	for sc.Scan() {
		n++
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 2 {
			return nil, fmt.Errorf("resolvers.txt line %d: address and name expected", n)
		}
		name := strings.Join(f[1:], " ")
		if strings.Contains(f[0], "/") {
			p, err := netip.ParsePrefix(f[0])
			if err != nil {
				return nil, fmt.Errorf("resolvers.txt line %d: %w", n, err)
			}
			r.prefixes = append(r.prefixes, resolverPrefix{p.Masked(), name})
			continue
		}
		a, err := netip.ParseAddr(f[0])
		if err != nil {
			return nil, fmt.Errorf("resolvers.txt line %d: %w", n, err)
		}
		r.addrs[a] = name
	}
	sort.Slice(r.prefixes, func(i, j int) bool { return r.prefixes[i].p.Bits() > r.prefixes[j].p.Bits() })
	return r, sc.Err()
}

// Lookup returns the name of the resolver at a, if it is a known public resolver.
func (r *Resolvers) Lookup(a netip.Addr) (string, bool) {
	a = a.Unmap()
	if n, ok := r.addrs[a]; ok {
		return n, true
	}
	for _, p := range r.prefixes {
		if p.p.Contains(a) {
			return p.name, true
		}
	}
	return "", false
}

// Len returns the number of entries.
func (r *Resolvers) Len() int { return len(r.addrs) + len(r.prefixes) }
