package detect

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/erwsim/watchpost/server/collector/internal/store"
)

// Finding is the result of a detection, before storage.
type Finding struct {
	Type    string
	Package string
	Label   string
	// Subject is what the finding is about within its window: one finding per (type, subject, window).
	Subject  string
	FromMS   int64 // window
	ToMS     int64
	Sev      int
	Summary  string
	Evidence map[string]any
	// Items are the elements of the finding (domains, capabilities, operations, ports, resolvers…): a new
	// element in an existing finding is reported again to Wazuh (see store.UpsertDetections).
	Items []string
}

// Labels gives the readable name of an application ("" when unknown).
type Labels map[string]string

func (l Labels) of(pkg string) string {
	if v := l[pkg]; v != "" {
		return v
	}
	return pkg
}

const hourMS = int64(time.Hour / time.Millisecond)
const dayMS = 24 * hourMS

// evidence lists are kept short (contract: a short, factual object).
const maxSample = 5

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- detect.upload_spike ------------------------------------------------------------------------

// UploadInput is the data of one hour of a device.
type UploadInput struct {
	HourMS int64
	Tx     map[string]int64 // bytes sent per application during the hour
	// History holds, for the applications above the floor, the bytes sent in each hour with traffic of
	// the 14 days before the hour.
	History map[string][]int64
	// Learning is true while the device has less than UploadLearnDays of net.usage history.
	Learning        bool
	ScreenOnMinutes int // minutes with the screen on during the hour (-1: unknown)
	Labels          Labels
}

func median(v []int64) int64 {
	if len(v) == 0 {
		return 0
	}
	s := append([]int64(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	if len(s)%2 == 1 {
		return s[len(s)/2]
	}
	return (s[len(s)/2-1] + s[len(s)/2]) / 2
}

// UploadSpike: bytes sent by an application during one hour > max(floor, k × its hourly median over 14
// days). The median is taken over the hours where the application sent something. While it is not
// meaningful — device history shorter than UploadLearnDays, or fewer than UploadMinActiveHrs hours of
// traffic for the application (new application) — only the floor applies ("learning").
func UploadSpike(in UploadInput, t Thresholds) []Finding {
	var out []Finding
	for _, pkg := range sortedKeys(in.Tx) {
		tx := in.Tx[pkg]
		if tx <= t.UploadFloorBytes {
			continue
		}
		hist := in.History[pkg]
		learning := in.Learning || len(hist) < UploadMinActiveHrs
		limit := t.UploadFloorBytes
		med := median(hist)
		if !learning {
			if k := int64(float64(med) * t.UploadFactor); k > limit {
				limit = k
			}
		}
		if tx <= limit {
			continue
		}
		ev := map[string]any{"tx_bytes": tx, "threshold_bytes": limit, "history_hours": len(hist), "learning": learning}
		basis := fmt.Sprintf("floor %s", formatBytes(t.UploadFloorBytes))
		if !learning {
			ev["median_bytes"] = med
			basis = fmt.Sprintf("threshold %s; hourly median over 14 days: %s", formatBytes(limit), formatBytes(med))
		} else {
			basis += ", not enough history for the median"
		}
		if in.ScreenOnMinutes >= 0 {
			ev["screen_on_minutes"] = in.ScreenOnMinutes
		}
		out = append(out, Finding{Type: TypeUploadSpike, Package: pkg, Subject: pkg, FromMS: in.HourMS, ToMS: in.HourMS + hourMS, Sev: 2,
			Summary:  fmt.Sprintf("%s sent %s in one hour (%s)%s", in.Labels.of(pkg), formatBytes(tx), basis, screenNote(in.ScreenOnMinutes)),
			Evidence: ev})
	}
	return out
}

func screenNote(min int) string {
	switch {
	case min < 0:
		return ""
	case min <= ScreenOffMaxMinutes:
		return ", screen off"
	}
	return fmt.Sprintf(", screen on %d min", min)
}

// --- connections: detect.fanout, detect.mail_ports, detect.dns_bypass ------------------------------

// Dest is a destination of an application with its number of connections.
type Dest struct {
	Package string
	Addr    netip.Addr
	Port    int // 0: unknown
	Count   int64
}

// ParseDest reads a connect_dest key: "ip:port", "[ipv6]:port" or "ip".
func ParseDest(key string) (netip.Addr, int, bool) {
	if ap, err := netip.ParseAddrPort(key); err == nil {
		return ap.Addr().Unmap(), int(ap.Port()), true
	}
	if a, err := netip.ParseAddr(strings.Trim(key, "[]")); err == nil {
		return a.Unmap(), 0, true
	}
	return netip.Addr{}, 0, false
}

// Dests converts stored rows (rows whose key is not an address are skipped).
func Dests(rows []store.ConnectRow) []Dest {
	out := make([]Dest, 0, len(rows))
	for _, r := range rows {
		a, port, ok := ParseDest(r.Key)
		if !ok {
			continue
		}
		out = append(out, Dest{Package: r.Package, Addr: a, Port: port, Count: r.Count})
	}
	return out
}

type destAgg struct {
	addrs map[netip.Addr]int64
	ports map[int]int64
	conns int64
}

func byPackage(dests []Dest, keep func(Dest) bool) map[string]*destAgg {
	out := map[string]*destAgg{}
	for _, d := range dests {
		if d.Package == "" || (keep != nil && !keep(d)) {
			continue
		}
		a := out[d.Package]
		if a == nil {
			a = &destAgg{addrs: map[netip.Addr]int64{}, ports: map[int]int64{}}
			out[d.Package] = a
		}
		a.addrs[d.Addr] += d.Count
		a.ports[d.Port] += d.Count
		a.conns += d.Count
	}
	return out
}

func (a *destAgg) sampleAddrs(n int) []any {
	type kv struct {
		a netip.Addr
		n int64
	}
	var l []kv
	for k, v := range a.addrs {
		l = append(l, kv{k, v})
	}
	sort.Slice(l, func(i, j int) bool {
		if l[i].n != l[j].n {
			return l[i].n > l[j].n
		}
		return l[i].a.Less(l[j].a)
	})
	out := []any{}
	for i := 0; i < len(l) && i < n; i++ {
		out = append(out, l[i].a.String())
	}
	return out
}

func (a *destAgg) topPorts(n int) []any {
	ports := make([]int, 0, len(a.ports))
	for p := range a.ports {
		if p > 0 {
			ports = append(ports, p)
		}
	}
	sort.Slice(ports, func(i, j int) bool {
		if a.ports[ports[i]] != a.ports[ports[j]] {
			return a.ports[ports[i]] > a.ports[ports[j]]
		}
		return ports[i] < ports[j]
	})
	out := []any{}
	for i := 0; i < len(ports) && i < n; i++ {
		out = append(out, ports[i])
	}
	return out
}

// MaxDistinct returns the largest number of distinct addresses of one application.
func MaxDistinct(dests []Dest) int {
	m := 0
	for _, a := range byPackage(dests, nil) {
		m = max(m, len(a.addrs))
	}
	return m
}

// Fanout: an application connected to more than N distinct addresses during one hour (N lower for an hour
// spent screen off).
func Fanout(hour int64, dests []Dest, screenOnMinutes int, labels Labels, t Thresholds) []Finding {
	limit := t.Fanout
	screenOff := screenOnMinutes >= 0 && screenOnMinutes <= ScreenOffMaxMinutes
	if screenOff {
		limit = min(limit, t.FanoutScreenOff)
	}
	agg := byPackage(dests, nil)
	var out []Finding
	for _, pkg := range sortedKeys(agg) {
		a := agg[pkg]
		if len(a.addrs) <= limit {
			continue
		}
		ev := map[string]any{"addresses": len(a.addrs), "connections": a.conns, "threshold": limit,
			"ports": a.topPorts(maxSample), "sample": a.sampleAddrs(maxSample)}
		if screenOnMinutes >= 0 {
			ev["screen_on_minutes"] = screenOnMinutes
		}
		out = append(out, Finding{Type: TypeFanout, Package: pkg, Subject: pkg, FromMS: hour, ToMS: hour + hourMS, Sev: 2,
			Summary: fmt.Sprintf("%s connected to %d distinct addresses in one hour (threshold %d%s)", labels.of(pkg), len(a.addrs), limit,
				map[bool]string{true: ", screen off", false: ""}[screenOff]),
			Evidence: ev})
	}
	return out
}

// MailPorts are the ports used to send e-mail (SMTP relay and submission).
var MailPorts = map[int]bool{25: true, 465: true, 587: true}

// MailPortsRule: an application that is not a known mail client connects to ports 25, 465 or 587 (dests
// of one day).
func MailPortsRule(day int64, dests []Dest, labels Labels, t Thresholds) []Finding {
	agg := byPackage(dests, func(d Dest) bool { return MailPorts[d.Port] && !t.MailClients[d.Package] })
	var out []Finding
	for _, pkg := range sortedKeys(agg) {
		a := agg[pkg]
		if a.conns < int64(t.MailMin) {
			continue
		}
		sev := 2
		if a.conns >= 100 || len(a.addrs) >= 20 {
			sev = 3 // volume of a spam relay
		}
		ports := a.topPorts(3)
		out = append(out, Finding{Type: TypeMailPorts, Package: pkg, Subject: pkg, FromMS: day, ToMS: day + dayMS, Sev: sev,
			Summary: fmt.Sprintf("%s, which is not a known mail client, connected %d times to mail-sending port %s of %d server(s)",
				labels.of(pkg), a.conns, joinInts(ports), len(a.addrs)),
			Evidence: map[string]any{"connections": a.conns, "addresses": len(a.addrs), "ports": ports, "sample": a.sampleAddrs(3)},
			Items:    strings.Split(joinInts(ports), ", ")})
	}
	return out
}

func joinInts(v []any) string {
	parts := make([]string, len(v))
	for i, x := range v {
		parts[i] = fmt.Sprint(x)
	}
	return strings.Join(parts, ", ")
}

// DNSBypass: an application connects to a known public DoH/DoT resolver (dests of one day). The second
// heuristic of the contract (massive connections to addresses never resolved) is not implemented, see the
// README.
func DNSBypass(day int64, dests []Dest, res *Resolvers, labels Labels, t Thresholds) []Finding {
	type hit struct {
		conns     int64
		endpoints map[string]int64
		providers map[string]bool
	}
	hits := map[string]*hit{}
	for _, d := range dests {
		if d.Package == "" || t.DNSBypassExempt[d.Package] || !t.DNSBypassPorts[d.Port] {
			continue
		}
		name, ok := res.Lookup(d.Addr)
		if !ok {
			continue
		}
		h := hits[d.Package]
		if h == nil {
			h = &hit{endpoints: map[string]int64{}, providers: map[string]bool{}}
			hits[d.Package] = h
		}
		h.conns += d.Count
		h.endpoints[netip.AddrPortFrom(d.Addr, uint16(d.Port)).String()] += d.Count
		h.providers[name] = true
	}
	var out []Finding
	for _, pkg := range sortedKeys(hits) {
		h := hits[pkg]
		if h.conns < int64(t.DNSBypassMin) {
			continue
		}
		eps := sortedKeys(h.endpoints)
		sort.SliceStable(eps, func(i, j int) bool { return h.endpoints[eps[i]] > h.endpoints[eps[j]] })
		if len(eps) > maxSample {
			eps = eps[:maxSample]
		}
		provs := sortedKeys(h.providers)
		out = append(out, Finding{Type: TypeDNSBypass, Package: pkg, Subject: pkg, FromMS: day, ToMS: day + dayMS, Sev: 2,
			Summary: fmt.Sprintf("%s talks directly to a public DNS resolver (%s, %s): its DNS requests escape the phone's filtering and log",
				labels.of(pkg), strings.Join(provs, ", "), eps[0]),
			Evidence: map[string]any{"connections": h.conns, "resolvers": toAny(eps), "providers": toAny(provs)}, Items: provs})
	}
	return out
}

func toAny(v []string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

// --- detect.threat_domain -----------------------------------------------------------------------

// ThreatInput is the data of one day of a device.
type ThreatInput struct {
	DayMS    int64
	Blocks   []store.ThreatBlock // domains blocked due to a threat list (AdGuard Home)
	Lookups  []store.DNSLookup   // net.dns lookups of these domains per application
	Browsers map[string]bool     // holders of the browser role (a click on a phishing link is less severe)
	Labels   Labels
}

// ThreatDomain: an application asked for a domain that AdGuard Home blocked due to a threat list. One
// finding per application and day, listing its domains (most requested first).
func ThreatDomain(in ThreatInput) []Finding {
	blocks := map[string]store.ThreatBlock{}
	for _, b := range in.Blocks {
		blocks[b.Domain] = b
	}
	byPkg := map[string][]store.DNSLookup{}
	for _, l := range in.Lookups {
		if _, ok := blocks[l.Domain]; ok && l.Package != "" {
			byPkg[l.Package] = append(byPkg[l.Package], l)
		}
	}
	var out []Finding
	for _, pkg := range sortedKeys(byPkg) {
		ls := byPkg[pkg]
		sort.Slice(ls, func(i, j int) bool {
			if ls[i].Count != ls[j].Count {
				return ls[i].Count > ls[j].Count
			}
			return ls[i].Domain < ls[j].Domain
		})
		var requests, blocked int64
		var domains, parts []string
		reasons := map[string]bool{}
		for _, l := range ls {
			b := blocks[l.Domain]
			requests += l.Count
			blocked += b.Blocked
			domains = append(domains, l.Domain)
			if len(parts) < 3 {
				parts = append(parts, fmt.Sprintf("%s x%d", l.Domain, l.Count))
			}
			if b.Reason != "" {
				reasons[strings.TrimPrefix(b.Reason, "List: ")] = true
			}
		}
		sev := 3
		if in.Browsers[pkg] || requests < 3 {
			sev = 2 // a link followed once in a browser, rather than an application calling its server
		}
		more := ""
		if len(domains) > len(parts) {
			more = fmt.Sprintf(" and %d other(s)", len(domains)-len(parts))
		}
		shown := domains
		if len(shown) > maxListed {
			shown = shown[:maxListed]
		}
		lists := sortedKeys(reasons)
		out = append(out, Finding{Type: TypeThreatDomain, Package: pkg, Subject: pkg, FromMS: in.DayMS, ToMS: in.DayMS + dayMS, Sev: sev,
			Summary: fmt.Sprintf("%s requested %d domain(s) blocked by a threat list: %s%s (%s)", in.Labels.of(pkg), len(domains),
				strings.Join(parts, ", "), more, strings.Join(lists, ", ")),
			Evidence: map[string]any{"domains": toAny(shown), "domain_count": len(domains), "requests": requests, "blocked": blocked,
				"lists": toAny(lists)},
			Items: domains})
	}
	return out
}

// maxListed bounds the lists of evidence (domains, capabilities…).
const maxListed = 10

// --- app.ops: detect.sms_abuse, detect.sensor_background -----------------------------------------

// OpsInput is the app.ops of one day of a device.
type OpsInput struct {
	DayMS int64
	Uses  []store.OpUse
	// SMSApps are the applications that held the default SMS role during the day (nil: unknown).
	SMSApps map[string]bool
	// System are the system applications (latest inventory).
	System map[string]bool
	// SensorExempt are the applications allowed to use the microphone or the camera in the background:
	// holders of the dialer, assistant and call screening roles.
	SensorExempt map[string]bool
	Labels       Labels
}

func opsOf(uses []store.OpUse) map[string]map[string]store.OpUse {
	out := map[string]map[string]store.OpUse{}
	for _, u := range uses {
		if out[u.Package] == nil {
			out[u.Package] = map[string]store.OpUse{}
		}
		out[u.Package][u.Op] = u
	}
	return out
}

// SMSAbuse: according to app.ops, an application other than the default SMS app sent SMS or tried to (at
// least SMSOtherMin attempts in the day, refused ones included: an application stopped by the SMS guard is
// as telling as one that succeeds; system applications excepted, and only when the SMS app is known), or any
// application attempted more than SMSDailyMax SMS in the day. The counters of app.ops are lower bounds.
// Silent without app.ops.
func SMSAbuse(in OpsInput, t Thresholds) []Finding {
	ops := opsOf(in.Uses)
	var out []Finding
	for _, pkg := range sortedKeys(ops) {
		sent, ok := ops[pkg]["send_sms"]
		attempts := sent.Count + sent.Rejected
		if !ok || attempts <= 0 {
			continue
		}
		other := in.SMSApps != nil && !in.SMSApps[pkg] && !in.System[pkg]
		refused := ""
		if sent.Rejected > 0 {
			refused = fmt.Sprintf(", %d refused by the system", sent.Rejected)
		}
		var reason, summary string
		switch {
		case other && attempts >= t.SMSOtherMin:
			reason = "not_default_sms_app"
			summary = fmt.Sprintf("%s, which is not the default SMS app, sent or tried to send %d SMS during the day (%d sent, %d of them in the background%s)",
				in.Labels.of(pkg), attempts, sent.Count, sent.Background, refused)
		case attempts > t.SMSDailyMax:
			reason = "volume"
			summary = fmt.Sprintf("%s sent or tried to send %d SMS during the day (threshold %d%s)", in.Labels.of(pkg), attempts, t.SMSDailyMax, refused)
		default:
			continue
		}
		ev := map[string]any{"reason": reason, "sent": sent.Count, "background": sent.Background, "rejected": sent.Rejected}
		if rc, ok := ops[pkg]["read_contacts"]; ok && rc.Count > 0 {
			ev["read_contacts"] = rc.Count
		}
		if in.SMSApps != nil {
			ev["default_sms_app"] = toAny(sortedKeys(in.SMSApps))
		}
		items := []string{reason}
		if sent.Rejected > 0 {
			items = append(items, "rejected")
		}
		out = append(out, Finding{Type: TypeSMSAbuse, Package: pkg, Subject: pkg, FromMS: in.DayMS, ToMS: in.DayMS + dayMS, Sev: 3,
			Summary: summary, Evidence: ev, Items: items})
	}
	return out
}

// SensorBackground: according to app.ops, the microphone or the camera used in the background by an
// application beyond a threshold per day (system applications and holders of the dialer, assistant and
// call screening roles excepted). One finding per application and day. Silent without app.ops.
func SensorBackground(in OpsInput, t Thresholds) []Finding {
	ops := opsOf(in.Uses)
	var out []Finding
	for _, pkg := range sortedKeys(ops) {
		if in.System[pkg] || in.SensorExempt[pkg] {
			continue
		}
		ev := map[string]any{}
		var items, parts []string
		for _, s := range []struct {
			op, key, name string
			min           int64
		}{{"record_audio", "microphone", "the microphone", t.MicBackgroundMin}, {"camera", "camera", "the camera", t.CameraBackgroundMin}} {
			u, ok := ops[pkg][s.op]
			if !ok || u.Background < s.min {
				continue
			}
			items = append(items, s.op)
			ev[s.key+"_background"], ev[s.key+"_count"] = u.Background, u.Count
			parts = append(parts, fmt.Sprintf("%s %d times (threshold %d)", s.name, u.Background, s.min))
		}
		if len(items) == 0 {
			continue
		}
		ev["ops"] = toAny(items)
		out = append(out, Finding{Type: TypeSensorBackground, Package: pkg, Subject: pkg, FromMS: in.DayMS, ToMS: in.DayMS + dayMS, Sev: 2,
			Summary:  fmt.Sprintf("%s used %s in the background during the day", in.Labels.of(pkg), strings.Join(parts, " and ")),
			Evidence: ev, Items: items})
	}
	return out
}

// --- detect.new_app_risky ------------------------------------------------------------------------

// Install is an app.installed event.
type Install struct {
	Package, Installer string
	TS                 int64
}

// Risk is an app.risk event.
type Risk struct {
	Package, Label, Level string
	Score                 int64
	Reasons               []string
	// Granted are the codes of the capabilities actually granted (contract §11.4: app.risk rates the declared
	// capabilities, "granted" tells which ones are granted).
	Granted   []string
	FromStore *bool
	TS        int64
}

// Capability is a sensitive capability obtained by an application (Kind: see CapabilityNames).
type Capability struct {
	Package, Kind string
	TS            int64
}

// CapabilityNames are the sensitive capabilities followed by detect.new_app_risky, with their severity.
var CapabilityNames = map[string]struct {
	Name string
	Sev  int
}{
	"accessibility":                     {"accessibility service", 2},
	"notification_listener":             {"notification reading", 2},
	"device_admin":                      {"device administrator", 2},
	"unknown_sources":                   {"installing other applications", 2},
	"overlay":                           {"drawing over other applications", 1},
	"vpn":                               {"VPN", 1},
	"role:sms":                          {"default SMS app", 2},
	"role:dialer":                       {"default dialer app", 2},
	"role:assistant":                    {"default assistant", 2},
	"role:call_screening":               {"call screening", 2},
	"role:keyboard":                     {"default keyboard", 2},
	"role:autofill":                     {"autofill (passwords)", 2},
	"permission:SEND_SMS":               {"sending SMS", 2},
	"permission:READ_SMS":               {"reading SMS", 2},
	"permission:RECEIVE_SMS":            {"receiving SMS", 2},
	"permission:RECEIVE_MMS":            {"receiving MMS", 2},
	"permission:READ_CALL_LOG":          {"call log", 2},
	"permission:PROCESS_OUTGOING_CALLS": {"outgoing calls", 2},
	"permission:CALL_PHONE":             {"phone calls", 2},
}

// NewAppInput gathers the application events around a day of a device.
type NewAppInput struct {
	Installs []Install
	Risks    []Risk
	Caps     []Capability
	Labels   Labels
}

// OwnPackage reports whether pkg is Watchpost itself (its agent and companion), never reported.
func OwnPackage(pkg string) bool {
	return pkg == "io.github.erwsim.watchpost" || strings.HasPrefix(pkg, "io.github.erwsim.watchpost.")
}

func hasCombo(reasons []string) bool {
	for _, r := range reasons {
		if strings.HasPrefix(r, "combo_") {
			return true
		}
	}
	return false
}

// NewAppRisky: an application of level "high" has just been installed (app.risk within 24 h of its
// app.installed), or an application installed less than 24 h ago obtains a sensitive capability. One finding
// per installation, whose window is the 24 hours following it, listing the capabilities obtained.
func NewAppRisky(in NewAppInput) []Finding {
	installs := append([]Install(nil), in.Installs...)
	sort.Slice(installs, func(i, j int) bool { return installs[i].TS < installs[j].TS })
	caps := append([]Capability(nil), in.Caps...)
	for _, r := range in.Risks {
		caps = append(caps, GrantedCapabilities(r)...)
	}
	sort.SliceStable(caps, func(i, j int) bool { return caps[i].TS < caps[j].TS })
	var out []Finding
	for _, ins := range installs {
		if ins.Package == "" || OwnPackage(ins.Package) {
			continue
		}
		from, to := ins.TS, ins.TS+NewAppWindow.Milliseconds()
		label := in.Labels.of(ins.Package)
		var best *Risk
		for i := range in.Risks {
			r := &in.Risks[i]
			if r.Package == ins.Package && r.TS >= from-hourMS && r.TS <= to && (best == nil || r.Score > best.Score ||
				(r.Score == best.Score && r.TS < best.TS)) {
				best = r
			}
		}
		if best != nil && best.Label != "" && in.Labels[ins.Package] == "" {
			label = best.Label
		}
		high := best != nil && best.Level == "high"
		sev := 0
		var items, names []string
		var first int64 = -1
		if high {
			items = append(items, "high_risk")
			sev = 2
			if hasCombo(best.Reasons) {
				sev = 3
			}
		}
		seen := map[string]bool{}
		for _, c := range caps {
			info, known := CapabilityNames[c.Kind]
			if c.Package != ins.Package || !known || seen[c.Kind] || c.TS < from || c.TS > to {
				continue
			}
			seen[c.Kind] = true
			items = append(items, c.Kind)
			names = append(names, info.Name)
			sev = max(sev, info.Sev)
			if first < 0 {
				first = c.TS
			}
		}
		if len(items) == 0 {
			continue
		}
		capsList := items
		if high {
			capsList = items[1:]
		}
		ev := map[string]any{"high_risk": high, "capabilities": toAny(capsList), "installer": ins.Installer, "installed_at": fmtMS(ins.TS)}
		if best != nil {
			ev["score"], ev["level"], ev["reasons"] = best.Score, best.Level, toAny(best.Reasons)
			if len(best.Granted) > 0 {
				ev["granted"] = toAny(best.Granted)
			}
			if best.FromStore != nil {
				ev["from_store"] = *best.FromStore
			}
		}
		var parts []string
		if high {
			parts = append(parts, fmt.Sprintf("high risk (score %d: %s)", best.Score, strings.Join(best.Reasons, ", ")))
		}
		if len(names) > 0 {
			ev["minutes_to_first_capability"] = (first - ins.TS) / 60000
			parts = append(parts, fmt.Sprintf("obtained within %s: %s", formatDuration(first-ins.TS), strings.Join(names, ", ")))
		}
		out = append(out, Finding{Type: TypeNewAppRisky, Package: ins.Package, Label: label, Subject: ins.Package,
			FromMS: from, ToMS: to, Sev: sev,
			Summary:  fmt.Sprintf("%s, installed on %s: %s", label, time.UnixMilli(ins.TS).UTC().Format("Jan 2, 15:04 UTC"), strings.Join(parts, "; ")),
			Evidence: ev, Items: items})
	}
	return out
}

// GroupDay merges the hourly findings of the same type and application into one finding per UTC day: the
// evidence of the peak hour (largest value of metric), with "hours" (hours above the threshold),
// "first_hour" and "peak_hour".
func GroupDay(fs []Finding, metric string) []Finding {
	type group struct {
		peak         Finding
		peakV        int64
		hours        int
		first        int64
		firstSummary string
	}
	groups := map[string]*group{}
	var keys []string
	for _, f := range fs {
		day := f.FromMS - mod(f.FromMS, dayMS)
		k := fmt.Sprintf("%s|%s|%d", f.Type, f.Package, day)
		v, _ := f.Evidence[metric].(int64)
		if iv, ok := f.Evidence[metric].(int); ok {
			v = int64(iv)
		}
		g := groups[k]
		if g == nil {
			g = &group{peak: f, peakV: v, first: f.FromMS}
			groups[k] = g
			keys = append(keys, k)
		} else {
			if v > g.peakV {
				g.peak, g.peakV = f, v
			}
			g.first = min(g.first, f.FromMS)
		}
		g.hours++
	}
	sort.Strings(keys)
	out := make([]Finding, 0, len(keys))
	for _, k := range keys {
		g := groups[k]
		f := g.peak
		ev := make(map[string]any, len(f.Evidence)+3)
		for kk, v := range f.Evidence {
			ev[kk] = v
		}
		ev["hours"], ev["first_hour"], ev["peak_hour"] = g.hours, fmtMS(g.first), fmtMS(f.FromMS)
		if g.hours > 1 {
			f.Summary += fmt.Sprintf("; %d hours above the threshold during the day (peak at %s)", g.hours,
				time.UnixMilli(f.FromMS).UTC().Format("15:04 UTC"))
		} else {
			f.Summary += fmt.Sprintf(" (%s)", time.UnixMilli(f.FromMS).UTC().Format("15:04 UTC"))
		}
		day := f.FromMS - mod(f.FromMS, dayMS)
		f.Subject, f.FromMS, f.ToMS, f.Evidence = f.Package, day, day+dayMS, ev
		out = append(out, f)
	}
	return out
}

func fmtMS(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z") }

func formatDuration(ms int64) string {
	switch m := ms / 60000; {
	case m < 1:
		return "less than a minute"
	case m < 60:
		return strconv.FormatInt(m, 10) + " min"
	default:
		return fmt.Sprintf("%d h %02d min", m/60, m%60)
	}
}

// formatBytes formats a byte count with binary units ("1.5 GiB").
func formatBytes(n int64) string {
	units := []string{"B", "KiB", "MiB", "GiB", "TiB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	s := strconv.FormatFloat(f, 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	return s + " " + units[i]
}
