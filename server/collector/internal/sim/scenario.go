package sim

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// Risk profile and usage of the applications (contract §11.2: app.risk, app.role, app.ops) for the healthy
// fleet of the simulated phone, ordinary behaviors that look like abuse to a naive rule (a video call, a
// cloud backup, an hour of heavy browsing), and the attack scenarios of `sim --scenario`, which produce
// sequences consistent over time to exercise the detections of §11.3, the Wazuh rules and the console
// without a phone. Everything here draws from its own random source (srng), so that the rest of a seeded
// simulation stays what it was.

// Scenario names (sim --scenario).
const (
	ScenarioHealthy   = "sain"
	ScenarioSMSFraud  = "fraude-sms"
	ScenarioBanking   = "cheval-de-troie"
	ScenarioProxy     = "proxy"
	ScenarioSpam      = "spam"
	ScenarioExfil     = "exfiltration"
	ScenarioDNSBypass = "contournement-dns"
	ScenarioSpy       = "espion"
	ScenarioSMSQuiet  = "sms-discret"
	ScenarioAll       = "tout"
)

// ScenarioInfo describes the scenarios for the command line help.
var ScenarioInfo = []struct{ Name, Desc string }{
	{ScenarioHealthy, "téléphone sain (par défaut) : aucune détection attendue avec les seuils par défaut"},
	{ScenarioSMSFraud, "fraude au SMS : appli sans icône installée hors store, permission d'envoi, ~2000 SMS par jour, contacts lus, panneau de commande bloqué ; garde SMS activée au bout de 24 h (envois refusés)"},
	{ScenarioBanking, "cheval de Troie bancaire : accessibilité + superposition + lecture des notifications, serveurs de commande bloqués par la liste de menaces"},
	{ScenarioProxy, "relais réseau (proxy résidentiel) : centaines d'adresses par heure la nuit, écran éteint"},
	{ScenarioSpam, "spam par e-mail : connexions aux ports 25 et 587 d'une appli qui n'est pas un client de messagerie"},
	{ScenarioExfil, "exfiltration : envoi de plus de 3 Gio en une heure par une appli de galerie"},
	{ScenarioDNSBypass, "contournement du DNS : appli qui interroge Cloudflare et Google en DoH/DoT"},
	{ScenarioSpy, "logiciel espion : micro et caméra en arrière-plan, administrateur de l'appareil"},
	{ScenarioSMSQuiet, "attaque vécue par le propriétaire : appli du Play Store sans icône, SEND_SMS obtenue 30 h après l'installation, envoi massif de SMS, aucun domaine de menace (à jouer aussi avec --app-ops=false)"},
	{ScenarioAll, "tous les scénarios d'attaque à la fois"},
}

// ParseScenarios checks a comma-separated list of scenarios ("tout" expands to every attack).
func ParseScenarios(v string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, s := range strings.Split(v, ",") {
		s = strings.TrimSpace(s)
		if s == "" || s == ScenarioHealthy {
			continue
		}
		names := []string{s}
		if s == ScenarioAll {
			names = []string{ScenarioSMSFraud, ScenarioBanking, ScenarioProxy, ScenarioSpam, ScenarioExfil, ScenarioDNSBypass, ScenarioSpy, ScenarioSMSQuiet}
		}
		for _, n := range names {
			known := false
			for _, i := range ScenarioInfo {
				known = known || i.Name == n
			}
			if !known {
				return nil, fmt.Errorf("scénario %q inconnu", s)
			}
			if !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
	}
	return out, nil
}

// opAcc accumulates the app.ops of the current hour.
type opAcc struct{ count, bg, rej int64 }

type opKey struct{ pkg, op string }

// attack is an application of an attack scenario.
type attack struct {
	name      string
	pkg       string
	label     string
	uid       int
	installer string
	start     time.Time // installation (or start of the abuse)
	spikeAt   time.Time // exfiltration: the hour of the spike; sms-discret: the grant of SEND_SMS
	started   bool
	perms     []string // dangerous permissions granted (inventory)
	granted   []string // capabilities granted (app.risk "granted")
}

// emitS is emit for the events drawn from srng (their ULID too).
func (g *Generator) emitS(ts time.Time, typ string, sev int, data map[string]any) {
	g.emit(ts, typ, sev, data)
	g.pend[len(g.pend)-1].rng = g.srng
}

// --- healthy fleet ---------------------------------------------------------------------------------

// riskOf scores an application of the healthy fleet like the agent would (contract §11.2): reasons from
// its installer and permissions; system applications and Vigie are capped at "low".
func riskOf(a *app) map[string]any {
	reasons := []string{}
	score := 0
	add := func(r string, w int) { reasons = append(reasons, r); score += w }
	fromStore := a.installer == "com.android.vending" || a.installer == "com.sec.android.app.samsungapps"
	if !a.system && !fromStore {
		add("sideloaded", 25)
		if a.installer != "com.android.vending" && a.installer != "" {
			add("unknown_installer", 10)
		}
	}
	for _, p := range a.dangerous {
		switch p[strings.LastIndexByte(p, '.')+1:] {
		case "SEND_SMS":
			add("sms_send", 20)
		case "READ_SMS":
			add("sms_read", 15)
		case "CALL_PHONE", "READ_CALL_LOG":
			if !contains(strings.Join(reasons, ","), "calls") {
				add("calls", 10)
			}
		case "ACCESS_BACKGROUND_LOCATION":
			add("background_location", 15)
		}
	}
	if a.notifies || a.pkg == "io.github.erwsim.vigie" {
		add("boot_receiver", 5)
	}
	if a.pkg == "io.github.erwsim.vigie" {
		add("device_admin", 15)
	}
	if a.target < 30 {
		add("old_target_sdk", 10)
	}
	score = min(score, 100)
	level := "low"
	switch {
	case a.system || a.pkg == "io.github.erwsim.vigie":
		score = min(score, 29) // capped at low, reasons kept (contract §11.2)
	case score >= 70:
		level = "high"
	case score >= 30:
		level = "medium"
	}
	// The score rates the declared capabilities (contract §11.4); "granted" lists those granted (in the
	// simulated catalog, the declared dangerous permissions are granted).
	var granted []string
	for _, r := range reasons {
		switch r {
		case "sms_send", "sms_read", "calls", "background_location", "device_admin":
			granted = append(granted, r)
		}
	}
	return map[string]any{"package": a.pkg, "label": a.label, "version_code": a.code, "installer": a.installer, "from_store": fromStore,
		"score": score, "level": level, "reasons": toAnyList(reasons), "granted": toAnyList(granted)}
}

func toAnyList(v []string) []any {
	out := make([]any, len(v))
	for i, s := range v {
		out[i] = s
	}
	return out
}

func riskSev(level string) int {
	switch level {
	case "high":
		return 2
	case "medium":
		return 1
	}
	return 0
}

// fleetStart emits what the agent reports at its first start: the risk profile of every installed
// application (app.risk). The default applications are not reported then (app.role: the first reading is
// the reference, without event); the collector knows them from app.special_access (default_apps).
func (g *Generator) fleetStart(t time.Time) {
	t = t.Add(4 * time.Second)
	for i := range apps {
		d := riskOf(&apps[i])
		g.emitS(t.Add(time.Duration(100+i*20)*time.Millisecond), "app.risk", riskSev(d["level"].(string)), d)
	}
}

// riskOnUpdate emits the app.risk of an updated or installed application.
func (g *Generator) riskFor(t time.Time, d map[string]any) {
	g.emitS(t.Add(800*time.Millisecond), "app.risk", riskSev(d["level"].(string)), d)
}

func (g *Generator) op(pkg, op string, count, bg int64) { g.opRej(pkg, op, count, bg, 0) }

// opRej records uses of an operation, rej of them refused by the system (a guard of the agent).
func (g *Generator) opRej(pkg, op string, count, bg, rej int64) {
	if !g.appOps || count+rej <= 0 {
		return
	}
	k := opKey{pkg, op}
	a := g.ops[k]
	if a == nil {
		a = &opAcc{}
		g.ops[k] = a
	}
	a.count += count
	a.bg += min(bg, count)
	a.rej += rej
}

func (g *Generator) spoisson(lambda float64) int64 {
	if lambda <= 0 {
		return 0
	}
	if lambda > 30 {
		return max(int64(math.Round(lambda+math.Sqrt(lambda)*g.srng.NormFloat64())), 0)
	}
	l, k, p := math.Exp(-lambda), int64(0), 1.0
	for {
		p *= g.srng.Float64()
		if p <= l {
			return k
		}
		k++
	}
}

// healthyOps draws the operations of the healthy fleet during [from, to).
func (g *Generator) healthyOps(from time.Time) {
	if !g.appOps {
		return
	}
	day := awake(from.In(g.loc))
	f := 0.15
	if day {
		f = 1
	}
	n := g.spoisson(0.5 * f)
	g.op("com.samsung.android.messaging", "send_sms", n, 0)
	g.op("com.samsung.android.messaging", "receive_sms", g.spoisson(0.8*f), g.spoisson(0.5*f))
	g.op("com.samsung.android.messaging", "read_sms", g.spoisson(1.2*f), 0)
	g.op("com.samsung.android.dialer", "call_phone", g.spoisson(0.15*f), 0)
	g.op("com.samsung.android.dialer", "read_call_log", g.spoisson(0.4*f), 0)
	g.op("com.samsung.android.dialer", "record_audio", g.spoisson(0.15*f), g.spoisson(0.1*f)) // calls, screen off at the ear
	g.op("com.whatsapp", "read_contacts", g.spoisson(0.4*f), g.spoisson(0.2*f))
	g.op("org.thoughtcrime.securesms", "read_contacts", g.spoisson(0.2*f), g.spoisson(0.1*f))
	g.op("com.google.android.gms", "fine_location", 3+g.spoisson(2), 3)
	g.op("com.google.android.gms", "get_accounts", g.spoisson(1), g.spoisson(1))
	g.op("io.github.erwsim.vigie", "fine_location", 10+g.spoisson(4), 10)
	g.op("com.google.android.googlequicksearchbox", "record_audio", g.spoisson(0.3*f), g.spoisson(0.2*f)) // assistant
	g.op("com.samsung.android.bixby.agent", "record_audio", g.spoisson(0.1*f), g.spoisson(0.1*f))
	if day {
		g.op("com.sec.android.app.camera", "camera", g.spoisson(0.4), 0)
		g.op("com.instagram.android", "camera", g.spoisson(0.15), 0)
		g.op("com.google.android.apps.maps", "fine_location", g.spoisson(0.5), 0)
		g.op("com.whatsapp", "record_audio", g.spoisson(0.3), 0) // voice messages
	}
}

// emitOps emits the app.ops of [from, to) (only the operations used, contract §11.2).
func (g *Generator) emitOps(from, to time.Time) {
	if !g.appOps {
		return
	}
	g.healthyOps(from)
	keys := make([]opKey, 0, len(g.ops))
	for k := range g.ops {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].pkg != keys[j].pkg {
			return keys[i].pkg < keys[j].pkg
		}
		return keys[i].op < keys[j].op
	})
	var list []any
	for _, k := range keys {
		a := g.ops[k]
		last := from.Add(time.Duration(g.srng.Int63n(int64(to.Sub(from))))).UTC().Format("2006-01-02T15:04:05.000Z07:00")
		list = append(list, map[string]any{"package": k.pkg, "op": k.op, "count": a.count, "background_count": a.bg,
			"rejected_count": a.rej, "last_ts": last})
	}
	g.ops = map[opKey]*opAcc{}
	if len(list) == 0 {
		return
	}
	g.emitS(to.Add(time.Duration(20+g.srng.Intn(20))*time.Second), "app.ops", 0, map[string]any{
		"from": from.UTC().Format(time.RFC3339), "to": to.UTC().Format(time.RFC3339), "apps": list})
}

func (g *Generator) addUsage(pkg string, rx, tx int64) {
	u := g.usage[pkg]
	if u == nil {
		u = &usageAcc{}
		g.usage[pkg] = u
	}
	u.rx += rx
	u.tx += tx
}

// sdns emits a lookup (and its connection) drawn from srng, fed to the fake AdGuard Home like the others.
func (g *Generator) sdns(t time.Time, pkg string, uid int, host string, port int) {
	addrs := addressesFor(host)
	list := make([]any, len(addrs))
	for i, a := range addrs {
		list[i] = a
	}
	d := map[string]any{"package": pkg, "uid": uid, "hostname": host, "addresses": list, "address_count": len(addrs)}
	g.emitS(t, "net.dns", 0, d)
	if g.onDNS != nil {
		// Fed when the generation reaches t (the hour is drawn in advance; AdGuard Home sees queries as they happen).
		g.later(t, func(at time.Time) { g.feedDNS(at, host, d) })
	}
	if port > 0 {
		g.emitS(t.Add(time.Duration(5+g.srng.Intn(300))*time.Millisecond), "net.connect", 0,
			map[string]any{"package": pkg, "uid": uid, "ip": addrs[0], "port": port})
	}
}

func (g *Generator) sconnect(t time.Time, pkg string, uid int, ip string, port int) {
	g.emitS(t, "net.connect", 0, map[string]any{"package": pkg, "uid": uid, "ip": ip, "port": port})
}

func (g *Generator) within(h time.Time) time.Time {
	return h.Add(time.Duration(g.srng.Int63n(int64(time.Hour))))
}

// healthyHour adds the ordinary heavy behaviors of a healthy phone during [h, h+1h): a WhatsApp video call
// now and then (hundreds of MiB sent), the nightly Samsung Cloud backup, an hour of heavy browsing in
// Chrome (dozens of addresses). They stay under the default thresholds on purpose: they are the false
// positives the defaults must not raise.
func (g *Generator) healthyHour(h time.Time) {
	lt := h.In(g.loc)
	day := awake(lt)
	// Video call: about three a week, in the evening.
	if day && lt.Hour() >= 19 && lt.Hour() < 22 && g.srng.Float64() < 0.14 {
		tx := int64(250+g.srng.Intn(200)) << 20
		g.addUsage("com.whatsapp", tx, tx)
		g.op("com.whatsapp", "record_audio", 1, int64(g.srng.Intn(2)))
		g.op("com.whatsapp", "camera", 1, 0)
	}
	// Cloud backup of the photos, at night on charge, every other night.
	if lt.Hour() == 2 && g.srng.Float64() < 0.5 {
		g.addUsage("com.samsung.android.scloud", int64(2+g.srng.Intn(5))<<20, int64(150+g.srng.Intn(700))<<20)
	}
	// An hour of heavy browsing once a day: 50 to 90 sites behind distinct addresses.
	if day && lt.Hour() == 21 && g.srng.Float64() < 0.8 {
		n := 50 + g.srng.Intn(41)
		for i := range n {
			host := fmt.Sprintf("cdn%d.site%d.example", i%3, i)
			g.sdns(g.within(h), "com.android.chrome", 10180, host, 443)
		}
		g.addUsage("com.android.chrome", int64(n)<<20, int64(n)<<16)
	}
}

// --- attack scenarios ------------------------------------------------------------------------------

// planAttacks prepares the scenarios: each attack starts at start (spread by a few minutes); end is the end
// of the simulated period when known (exfiltration spike placed before it).
func (g *Generator) planAttacks(names []string, start, end time.Time) {
	for i, n := range names {
		a := &attack{name: n, start: start.Add(time.Duration(i*7+g.srng.Intn(5)) * time.Minute), uid: 10900 + i}
		switch n {
		case ScenarioSMSFraud:
			a.pkg, a.label, a.installer = "com.flashlight.pro.tools", "Lampe Torche Pro", "com.google.android.packageinstaller"
		case ScenarioBanking:
			a.pkg, a.label, a.installer = "com.android.systemupdate.service", "Mise à jour du système", "com.google.android.packageinstaller"
		case ScenarioProxy:
			a.pkg, a.label, a.installer = "com.puzzle.relax.free", "Puzzle Relax", "com.android.vending"
		case ScenarioSpam:
			a.pkg, a.label, a.installer = "com.cleaner.boost.free", "Nettoyeur Boost", "com.android.vending"
		case ScenarioExfil:
			a.pkg, a.label, a.installer = "com.gallery.vault.hide", "Coffre Photos", "com.android.vending"
			spike := a.start.Add(36 * time.Hour)
			switch {
			case end.IsZero():
				spike = a.start.Add(time.Hour) // live: an hour after the start
			case spike.After(end.Add(-2 * time.Hour)):
				spike = end.Add(-2 * time.Hour)
			}
			if spike.Before(a.start.Add(time.Hour)) {
				spike = a.start.Add(time.Hour)
			}
			a.spikeAt = spike.Truncate(time.Hour)
		case ScenarioDNSBypass:
			a.pkg, a.label, a.installer = "com.fastvpn.browser", "Navigateur Rapide", "com.android.vending"
		case ScenarioSpy:
			a.pkg, a.label, a.installer = "com.android.battery.service", "Battery Service", "com.google.android.packageinstaller"
		case ScenarioSMSQuiet:
			a.pkg, a.label, a.installer = "com.coupons.promo.deals", "Promo Coupons", "com.android.vending"
			grant := a.start.Add(30 * time.Hour)
			switch {
			case end.IsZero():
				grant = a.start.Add(30 * time.Minute) // live: soon
			case grant.After(end.Add(-6 * time.Hour)):
				grant = end.Add(-6 * time.Hour)
			}
			if grant.Before(a.start.Add(25 * time.Hour)) {
				grant = a.start.Add(25 * time.Hour) // beyond the 24 h of detect.new_app_risky when the history allows it
				if !end.IsZero() && grant.After(end.Add(-time.Hour)) {
					grant = a.start.Add(time.Hour)
				}
			}
			a.spikeAt = grant
		}
		g.attacks = append(g.attacks, a)
	}
}

// attackRisk is the app.risk of an attack application: the declared capabilities, and those granted.
func attackRisk(a *attack) map[string]any {
	var reasons []string
	score := 0
	switch a.name {
	case ScenarioSMSFraud:
		reasons, score = []string{"sideloaded", "unknown_installer", "no_launcher_icon", "sms_send", "boot_receiver", "combo_sms_fraud"}, 91
	case ScenarioBanking:
		reasons, score = []string{"sideloaded", "unknown_installer", "no_launcher_icon", "accessibility_service", "overlay", "notification_listener",
			"install_packages", "combo_banking_trojan"}, 97
	case ScenarioSpy:
		reasons, score = []string{"sideloaded", "unknown_installer", "no_launcher_icon", "background_location", "mic_camera_background",
			"device_admin", "boot_receiver", "combo_stalkerware"}, 95
	case ScenarioProxy, ScenarioExfil:
		reasons, score = []string{"boot_receiver"}, 10
	case ScenarioSpam:
		reasons, score = []string{"boot_receiver", "overlay"}, 25
	case ScenarioDNSBypass:
		reasons, score = []string{"vpn_service"}, 20
	case ScenarioSMSQuiet:
		// A store application: the agent's scorer gives such a profile "medium" (30-69), not "high".
		reasons, score = []string{"no_launcher_icon", "sms_send", "boot_receiver", "combo_sms_fraud"}, 57
	}
	level := "low"
	switch {
	case score >= 70:
		level = "high"
	case score >= 30:
		level = "medium"
	}
	return map[string]any{"package": a.pkg, "label": a.label, "version_code": 7, "installer": a.installer,
		"from_store": a.installer == "com.android.vending", "score": score, "level": level, "reasons": toAnyList(reasons),
		"granted": toAnyList(a.granted)}
}

// specialAccess is the app.special_access of the phone with extra entries (component names "pkg/class").
func specialAccess(extra map[string][]string) map[string]any {
	lists := map[string][]string{
		"accessibility_services": {},
		"notification_listeners": {"io.github.erwsim.vigie/io.github.erwsim.vigie.collect.NotificationCollector", "com.samsung.android.app.watchmanager/.NotificationListener"},
		"device_admins":          {"io.github.erwsim.vigie/.admin.VigieAdminReceiver", "com.google.android.gms/.mdm.receivers.MdmDeviceAdminReceiver"},
		"overlay_apps":           {"com.samsung.android.app.cocktailbarservice"},
		"unknown_sources_apps":   {},
		"usage_access_apps":      {"io.github.erwsim.vigie", "com.google.android.gms", "com.samsung.android.lool"},
		"vpn_apps":               {},
	}
	for k, v := range extra {
		lists[k] = append(lists[k], v...)
	}
	out := map[string]any{"default_apps": map[string]any{"browser": "com.android.chrome", "sms": "com.samsung.android.messaging",
		"dialer": "com.samsung.android.dialer", "home": "com.sec.android.app.launcher", "assistant": "com.google.android.googlequicksearchbox"}}
	for k, v := range lists {
		out[k] = toAnyList(v)
	}
	return out
}

// smsGuardAfter is when the owner turns the SMS guard on in the SMS fraud scenario.
const smsGuardAfter = 24 * time.Hour

// attackStart emits the installation of an attack application and what follows within minutes.
func (g *Generator) attackStart(a *attack) {
	t := a.start
	sev := 0
	if a.installer != "com.android.vending" {
		sev = 2 // installed outside a store
	}
	g.emitS(t, "app.installed", sev, map[string]any{"package": a.pkg, "version_name": "1.0." + fmt.Sprint(g.srng.Intn(9)), "version_code": 7,
		"installer": a.installer, "signer_sha256": sha256Hex("signer:" + a.pkg)})
	g.emitS(t.Add(100*time.Millisecond), "security.log", 0, map[string]any{"tag": "package_installed", "level": "info",
		"log_id": g.srng.Intn(1 << 20), "fields": map[string]any{"package": a.pkg, "version_code": 7, "user_id": 0}})
	g.riskFor(t, attackRisk(a))
	perm := func(after time.Duration, p string) {
		g.later(t.Add(after), func(at time.Time) {
			g.emitS(at, "app.permission_changed", 0, map[string]any{"package": a.pkg, "permission": "android.permission." + p, "granted": true})
			a.perms = append(a.perms, "android.permission."+p)
		})
	}
	// The agent scores again when what is granted changes (app.risk with its "granted" list).
	grantedAt := func(after time.Duration, codes ...string) {
		g.later(t.Add(after), func(at time.Time) {
			a.granted = append(a.granted, codes...)
			g.riskFor(at, attackRisk(a))
		})
	}
	switch a.name {
	case ScenarioSMSFraud:
		perm(3*time.Minute, "SEND_SMS")
		perm(3*time.Minute+2*time.Second, "READ_CONTACTS")
		grantedAt(4*time.Minute, "sms_send")
		// A day later the owner turns the SMS guard on (contract §11.1): the attempts go on, refused.
		g.later(t.Add(smsGuardAfter), func(at time.Time) {
			g.emitS(at, "security.policy", 0, map[string]any{"action": "guard_enabled", "target": "sms", "profile": "guard:sms", "ok": true})
			g.emitS(at.Add(200*time.Millisecond), "security.policy", 1, map[string]any{"action": "permission_denied", "target": a.pkg,
				"permission": "android.permission.SEND_SMS", "profile": "guard:sms", "ok": true})
			g.emitS(at.Add(300*time.Millisecond), "app.permission_changed", 0, map[string]any{"package": a.pkg,
				"permission": "android.permission.SEND_SMS", "granted": false})
			a.perms = nil
		})
	case ScenarioBanking:
		perm(2*time.Minute, "RECEIVE_SMS")
		g.emitS(t.Add(6*time.Minute), "app.special_access", 0, specialAccess(map[string][]string{
			"accessibility_services": {a.pkg + "/.svc.AccessService"}, "notification_listeners": {a.pkg + "/.svc.NotifyService"},
			"overlay_apps": {a.pkg}}))
		grantedAt(7*time.Minute, "accessibility_service", "notification_listener", "overlay")
		// The usual way of SMS trojans: being made the default SMS app (accessibility clicks the dialog).
		g.emitS(t.Add(8*time.Minute), "app.role", 2, map[string]any{"role": "sms", "old": "com.samsung.android.messaging", "new": a.pkg})
	case ScenarioSpy:
		perm(2*time.Minute, "RECORD_AUDIO")
		perm(2*time.Minute+time.Second, "CAMERA")
		perm(2*time.Minute+2*time.Second, "ACCESS_BACKGROUND_LOCATION")
		g.emitS(t.Add(5*time.Minute), "app.special_access", 0, specialAccess(map[string][]string{"device_admins": {a.pkg + "/.AdminReceiver"}}))
		grantedAt(6*time.Minute, "background_location", "mic_camera_background", "device_admin")
	case ScenarioDNSBypass:
		g.emitS(t.Add(4*time.Minute), "app.special_access", 0, specialAccess(map[string][]string{"vpn_apps": {a.pkg}}))
	case ScenarioSMSQuiet:
		// SEND_SMS obtained long after the installation (here without the SMS guard).
		after := a.spikeAt.Sub(t)
		perm(after, "SEND_SMS")
		grantedAt(after+time.Minute, "sms_send")
	}
}

// attackInventory returns the entries of the attack applications for app.inventory.
func (g *Generator) attackInventory(t time.Time) []any {
	var out []any
	for _, a := range g.attacks {
		if !a.started || a.start.After(t) {
			continue
		}
		perms := make([]any, len(a.perms))
		for i, p := range a.perms {
			perms[i] = p
		}
		out = append(out, map[string]any{"package": a.pkg, "label": a.label, "version_name": "1.0.3", "version_code": 7, "installer": a.installer,
			"system": false, "enabled": true, "suspended": false, "hidden": false, "target_sdk": 34,
			"first_install": a.start.UTC().Format(time.RFC3339), "last_update": a.start.UTC().Format(time.RFC3339),
			"signer_sha256": sha256Hex("signer:" + a.pkg), "granted_dangerous": perms})
	}
	return out
}

func (g *Generator) randIP(prefixes ...string) string {
	p := prefixes[g.srng.Intn(len(prefixes))]
	return fmt.Sprintf("%s.%d.%d.%d", p, g.srng.Intn(256), g.srng.Intn(256), 1+g.srng.Intn(254))
}

// attackHour produces the activity of an attack during [h, h+1h).
func (g *Generator) attackHour(a *attack, h time.Time) {
	from := h
	if min := a.start.Add(10 * time.Minute); min.After(from) {
		from = min // the activity starts a few minutes after the installation
	}
	if !from.Before(h.Add(time.Hour)) {
		return
	}
	at := func() time.Time { return from.Add(time.Duration(g.srng.Int63n(int64(h.Add(time.Hour).Sub(from))))) }
	frac := h.Add(time.Hour).Sub(from).Hours()
	lt := h.In(g.loc)
	night := lt.Hour() >= 1 && lt.Hour() < 6
	switch a.name {
	case ScenarioSMSFraud:
		n := g.spoisson(85 * frac) // ~2000 per day, around the clock
		if h.Before(a.start.Add(smsGuardAfter)) {
			g.op(a.pkg, "send_sms", n, n)
		} else {
			g.opRej(a.pkg, "send_sms", 0, 0, n) // refused by the SMS guard
		}
		g.op(a.pkg, "read_contacts", 1, 1)
		g.op(a.pkg, "receive_sms", g.spoisson(2*frac), g.spoisson(2*frac))
		for range g.spoisson(3 * frac) {
			g.sdns(at(), a.pkg, a.uid, "panel.sms-gateway-pay.example", 443)
		}
		g.addUsage(a.pkg, int64(20+g.srng.Intn(80))<<10, int64(10+g.srng.Intn(40))<<10)
	case ScenarioBanking:
		for range g.spoisson(6 * frac) {
			host := []string{"api.secure-bank-sync.example", "gate.cdn-update-check.example"}[g.srng.Intn(2)]
			g.sdns(at(), a.pkg, a.uid, host, 443)
		}
		g.op(a.pkg, "receive_sms", g.spoisson(0.3*frac), g.spoisson(0.3*frac))
		g.op(a.pkg, "read_sms", g.spoisson(0.3*frac), g.spoisson(0.3*frac))
	case ScenarioProxy:
		g.sdns(at(), a.pkg, a.uid, "relay.proxy-earn.example", 443)
		if night {
			n := 320 + g.srng.Intn(160)
			seen := map[string]bool{}
			for len(seen) < n {
				ip := g.randIP("31", "45", "62", "77", "91", "103", "176", "185", "193", "212")
				if seen[ip] {
					continue
				}
				seen[ip] = true
				g.sconnect(at(), a.pkg, a.uid, ip, []int{443, 443, 443, 80, 8080}[g.srng.Intn(5)])
			}
			g.addUsage(a.pkg, int64(300+g.srng.Intn(300))<<20, int64(250+g.srng.Intn(300))<<20)
		} else {
			g.addUsage(a.pkg, int64(1+g.srng.Intn(3))<<20, int64(1+g.srng.Intn(2))<<19)
		}
	case ScenarioSpam:
		servers := 20 + g.srng.Intn(20)
		for i := range servers {
			ip := g.randIP("64", "66", "98", "104", "209")
			port := 587
			if i%4 == 0 {
				port = 25
			}
			for range 1 + g.srng.Intn(3) {
				g.sconnect(at(), a.pkg, a.uid, ip, port)
			}
		}
		g.addUsage(a.pkg, int64(1+g.srng.Intn(2))<<20, int64(5+g.srng.Intn(10))<<20)
	case ScenarioExfil:
		if h.Equal(a.spikeAt) {
			g.addUsage(a.pkg, int64(4+g.srng.Intn(4))<<20, int64(3200+g.srng.Intn(800))<<20)
			for range 40 {
				g.sdns(at(), a.pkg, a.uid, "uploads.files-drop.example", 443)
			}
		} else {
			g.addUsage(a.pkg, int64(1+g.srng.Intn(4))<<20, int64(1+g.srng.Intn(3))<<20)
		}
	case ScenarioDNSBypass:
		for range 3 + g.srng.Intn(10) {
			ep := []struct {
				ip   string
				port int
			}{{"1.1.1.1", 443}, {"1.0.0.1", 443}, {"8.8.8.8", 853}, {"2606:4700:4700::1111", 443}}[g.srng.Intn(4)]
			g.sconnect(at(), a.pkg, a.uid, ep.ip, ep.port)
		}
		g.addUsage(a.pkg, int64(5+g.srng.Intn(20))<<20, int64(1+g.srng.Intn(3))<<20)
	case ScenarioSMSQuiet:
		// A small hourly poll of its server (in no threat list), then, once SEND_SMS is granted, mass sending.
		g.sdns(at(), a.pkg, a.uid, "api.promo-coupons-cdn.example", 443)
		g.addUsage(a.pkg, int64(10+g.srng.Intn(30))<<10, int64(5+g.srng.Intn(20))<<10)
		if !h.Add(time.Hour).Before(a.spikeAt) {
			part := frac
			if a.spikeAt.After(h) {
				part = h.Add(time.Hour).Sub(a.spikeAt).Hours()
			}
			n := g.spoisson(85 * part)
			g.op(a.pkg, "send_sms", n, n)
		}
	case ScenarioSpy:
		n := g.spoisson(4 * frac) // short recordings, every 15 min or so
		g.op(a.pkg, "record_audio", n, n)
		if lt.Hour()%3 == 0 {
			g.op(a.pkg, "camera", 1, 1)
		}
		g.op(a.pkg, "fine_location", 4, 4)
		g.addUsage(a.pkg, int64(1+g.srng.Intn(2))<<20, int64(2+g.srng.Intn(6))<<20)
	}
}

// hourBoundary is called when the generation enters the hour h: the app.ops of the previous hour are
// emitted, then the activity of the healthy extras and of the attacks for [h, h+1h) is generated.
func (g *Generator) hourBoundary(prev, h time.Time) {
	g.emitOps(prev, h)
	g.healthyHour(h)
	for _, a := range g.attacks {
		if a.started {
			g.attackHour(a, h)
		}
	}
}

// startAttacks starts the attacks whose installation time is reached before t, with the activity of the
// hours already begun.
func (g *Generator) startAttacks(t time.Time) {
	for _, a := range g.attacks {
		if a.started || !a.start.Before(t) {
			continue
		}
		a.started = true
		g.attackStart(a)
		for h := a.start.Truncate(time.Hour); !h.After(g.usageHour); h = h.Add(time.Hour) {
			g.attackHour(a, h)
		}
	}
}

// uidOf returns the uid of an application of the fleet or of an attack.
func (g *Generator) uidOf(pkg string) int {
	if a := appByPkg(pkg); a != nil {
		return a.uid
	}
	for _, a := range g.attacks {
		if a.pkg == pkg {
			return a.uid
		}
	}
	return 0
}
