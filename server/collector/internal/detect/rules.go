package detect

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/store"
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
		basis := fmt.Sprintf("plancher %s", bytesFR(t.UploadFloorBytes))
		if !learning {
			ev["median_bytes"] = med
			basis = fmt.Sprintf("seuil %s ; médiane horaire sur 14 jours : %s", bytesFR(limit), bytesFR(med))
		} else {
			basis += ", historique insuffisant pour la médiane"
		}
		if in.ScreenOnMinutes >= 0 {
			ev["screen_on_minutes"] = in.ScreenOnMinutes
		}
		out = append(out, Finding{Type: TypeUploadSpike, Package: pkg, Subject: pkg, FromMS: in.HourMS, ToMS: in.HourMS + hourMS, Sev: 2,
			Summary:  fmt.Sprintf("%s a envoyé %s en une heure (%s)%s", in.Labels.of(pkg), bytesFR(tx), basis, screenNote(in.ScreenOnMinutes)),
			Evidence: ev})
	}
	return out
}

func screenNote(min int) string {
	switch {
	case min < 0:
		return ""
	case min <= ScreenOffMaxMinutes:
		return ", écran éteint"
	}
	return fmt.Sprintf(", écran allumé %d min", min)
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
			Summary: fmt.Sprintf("%s s'est connectée à %d adresses distinctes en une heure (seuil %d%s)", labels.of(pkg), len(a.addrs), limit,
				map[bool]string{true: ", écran éteint", false: ""}[screenOff]),
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
			Summary: fmt.Sprintf("%s, qui n'est pas un client de messagerie connu, s'est connectée %d fois au port d'envoi de courriel %s de %d serveur(s)",
				labels.of(pkg), a.conns, joinInts(ports), len(a.addrs)),
			Evidence: map[string]any{"connections": a.conns, "addresses": len(a.addrs), "ports": ports, "sample": a.sampleAddrs(3)}})
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
			Summary: fmt.Sprintf("%s s'adresse directement à un résolveur DNS public (%s, %s) : ses requêtes DNS échappent au filtrage et au journal du téléphone",
				labels.of(pkg), strings.Join(provs, ", "), eps[0]),
			Evidence: map[string]any{"connections": h.conns, "resolvers": toAny(eps), "providers": toAny(provs)}})
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

// ThreatDomain: an application asked for a domain that AdGuard Home blocked due to a threat list.
func ThreatDomain(in ThreatInput) []Finding {
	blocks := map[string]store.ThreatBlock{}
	for _, b := range in.Blocks {
		blocks[b.Domain] = b
	}
	lookups := append([]store.DNSLookup(nil), in.Lookups...)
	sort.Slice(lookups, func(i, j int) bool {
		if lookups[i].Package != lookups[j].Package {
			return lookups[i].Package < lookups[j].Package
		}
		return lookups[i].Domain < lookups[j].Domain
	})
	var out []Finding
	for _, l := range lookups {
		b, ok := blocks[l.Domain]
		if !ok || l.Package == "" {
			continue
		}
		sev := 3
		if in.Browsers[l.Package] || l.Count < 3 {
			sev = 2 // a link followed once in a browser, rather than an application calling its server
		}
		out = append(out, Finding{Type: TypeThreatDomain, Package: l.Package, Subject: l.Package + "|" + l.Domain,
			FromMS: in.DayMS, ToMS: in.DayMS + dayMS, Sev: sev,
			Summary: fmt.Sprintf("%s a demandé %s (%d fois), bloqué par une liste de menaces (%s)", in.Labels.of(l.Package), l.Domain,
				l.Count, strings.TrimPrefix(b.Reason, "Liste : ")),
			Evidence: map[string]any{"domain": l.Domain, "requests": l.Count, "blocked": b.Blocked, "reason": b.Reason}})
	}
	return out
}

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
			refused = fmt.Sprintf(", %d refusés par le système", sent.Rejected)
		}
		var reason, summary string
		switch {
		case other && attempts >= t.SMSOtherMin:
			reason = "not_default_sms_app"
			summary = fmt.Sprintf("%s, qui n'est pas l'application SMS par défaut, a envoyé ou tenté d'envoyer %d SMS dans la journée (%d envoyés dont %d en arrière-plan%s)",
				in.Labels.of(pkg), attempts, sent.Count, sent.Background, refused)
		case attempts > t.SMSDailyMax:
			reason = "volume"
			summary = fmt.Sprintf("%s a envoyé ou tenté d'envoyer %d SMS dans la journée (seuil %d%s)", in.Labels.of(pkg), attempts, t.SMSDailyMax, refused)
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
		out = append(out, Finding{Type: TypeSMSAbuse, Package: pkg, Subject: pkg, FromMS: in.DayMS, ToMS: in.DayMS + dayMS, Sev: 3,
			Summary: summary, Evidence: ev})
	}
	return out
}

// SensorBackground: according to app.ops, the microphone or the camera used in the background by an
// application beyond a threshold per day (system applications and holders of the dialer, assistant and
// call screening roles excepted). Silent without app.ops.
func SensorBackground(in OpsInput, t Thresholds) []Finding {
	ops := opsOf(in.Uses)
	var out []Finding
	for _, pkg := range sortedKeys(ops) {
		if in.System[pkg] || in.SensorExempt[pkg] {
			continue
		}
		for _, s := range []struct {
			op, name string
			min      int64
		}{{"record_audio", "le micro", t.MicBackgroundMin}, {"camera", "la caméra", t.CameraBackgroundMin}} {
			u, ok := ops[pkg][s.op]
			if !ok || u.Background < s.min {
				continue
			}
			out = append(out, Finding{Type: TypeSensorBackground, Package: pkg, Subject: pkg + "|" + s.op, FromMS: in.DayMS, ToMS: in.DayMS + dayMS,
				Sev:      2,
				Summary:  fmt.Sprintf("%s a utilisé %s %d fois en arrière-plan dans la journée (seuil %d)", in.Labels.of(pkg), s.name, u.Background, s.min),
				Evidence: map[string]any{"op": s.op, "background_count": u.Background, "count": u.Count}})
		}
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
	FromStore             *bool
	TS                    int64
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
	"accessibility":                     {"service d'accessibilité", 2},
	"notification_listener":             {"lecture des notifications", 2},
	"device_admin":                      {"administrateur de l'appareil", 2},
	"unknown_sources":                   {"installation d'autres applications", 2},
	"overlay":                           {"superposition aux autres applications", 1},
	"vpn":                               {"VPN", 1},
	"role:sms":                          {"application SMS par défaut", 2},
	"role:dialer":                       {"application Téléphone par défaut", 2},
	"role:assistant":                    {"assistant par défaut", 2},
	"role:call_screening":               {"filtrage des appels", 2},
	"permission:SEND_SMS":               {"envoi de SMS", 2},
	"permission:READ_SMS":               {"lecture des SMS", 2},
	"permission:RECEIVE_SMS":            {"réception des SMS", 2},
	"permission:RECEIVE_MMS":            {"réception des MMS", 2},
	"permission:READ_CALL_LOG":          {"journal d'appels", 2},
	"permission:PROCESS_OUTGOING_CALLS": {"appels sortants", 2},
	"permission:CALL_PHONE":             {"appels téléphoniques", 2},
}

// NewAppInput gathers the application events around a day of a device.
type NewAppInput struct {
	Installs []Install
	Risks    []Risk
	Caps     []Capability
	Labels   Labels
}

// OwnPackage reports whether pkg is Vigie itself (its agent and companion), never reported.
func OwnPackage(pkg string) bool {
	return pkg == "io.github.erwsim.vigie" || strings.HasPrefix(pkg, "io.github.erwsim.vigie.")
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
// app.installed), or an application installed less than 24 h ago obtains a sensitive capability. The
// window of a finding is the 24 hours following the installation.
func NewAppRisky(in NewAppInput) []Finding {
	installs := append([]Install(nil), in.Installs...)
	sort.Slice(installs, func(i, j int) bool { return installs[i].TS < installs[j].TS })
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
		if best != nil && best.Level == "high" {
			sev := 2
			if hasCombo(best.Reasons) {
				sev = 3
			}
			ev := map[string]any{"trigger": "high_risk", "score": best.Score, "level": best.Level, "reasons": toAny(best.Reasons),
				"installer": ins.Installer, "installed_at": fmtMS(ins.TS)}
			if best.FromStore != nil {
				ev["from_store"] = *best.FromStore
			}
			out = append(out, Finding{Type: TypeNewAppRisky, Package: ins.Package, Label: label, Subject: ins.Package + "|high_risk",
				FromMS: from, ToMS: to, Sev: sev,
				Summary: fmt.Sprintf("Application à risque élevé installée : %s (score %d ; %s)", label, best.Score,
					strings.Join(best.Reasons, ", ")),
				Evidence: ev})
		}
		seen := map[string]bool{}
		caps := append([]Capability(nil), in.Caps...)
		sort.SliceStable(caps, func(i, j int) bool { return caps[i].TS < caps[j].TS })
		for _, c := range caps {
			info, known := CapabilityNames[c.Kind]
			if c.Package != ins.Package || !known || seen[c.Kind] || c.TS < from || c.TS > to {
				continue
			}
			seen[c.Kind] = true
			ev := map[string]any{"trigger": "capability", "capability": c.Kind, "installed_at": fmtMS(ins.TS),
				"minutes_after_install": (c.TS - ins.TS) / 60000, "installer": ins.Installer}
			if best != nil {
				ev["level"], ev["score"] = best.Level, best.Score
			}
			out = append(out, Finding{Type: TypeNewAppRisky, Package: ins.Package, Label: label, Subject: ins.Package + "|" + c.Kind,
				FromMS: from, ToMS: to, Sev: info.Sev,
				Summary:  fmt.Sprintf("%s, installée il y a %s, a obtenu : %s", label, durationFR(c.TS-ins.TS), info.Name),
				Evidence: ev})
		}
	}
	return out
}

func fmtMS(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z") }

func durationFR(ms int64) string {
	switch m := ms / 60000; {
	case m < 1:
		return "moins d'une minute"
	case m < 60:
		return strconv.FormatInt(m, 10) + " min"
	default:
		return fmt.Sprintf("%d h %02d", m/60, m%60)
	}
}

// bytesFR formats a byte count the French way ("1,5 Gio").
func bytesFR(n int64) string {
	units := []string{"o", "Kio", "Mio", "Gio", "Tio"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d o", n)
	}
	s := strconv.FormatFloat(f, 'f', 1, 64)
	s = strings.TrimSuffix(s, ".0")
	return strings.Replace(s, ".", ",", 1) + " " + units[i]
}
