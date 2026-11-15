// Package sim generates realistic Vigie events covering the whole catalog of
// contract §2: a plausible daily routine around Paris (GPS track, Wi-Fi and
// cells, screen sessions, foreground apps, notifications), DNS lookups and
// connections of Google/Samsung/user packages, hourly network usage, daily
// inventories and posture, and a scenario of rare and severe events.
package sim

import (
	"fmt"
	"math"
	"math/rand"
	"sort"
	"time"
	_ "time/tzdata" // Europe/Paris in minimal images
)

// Event is one generated event, in the wire format of contract §1.
type Event struct {
	ID        string         `json:"id"`
	TS        string         `json:"ts"`
	Seq       int64          `json:"seq"`
	BootID    string         `json:"boot_id"`
	ElapsedMS int64          `json:"elapsed_ms"`
	Type      string         `json:"type"`
	Sev       int            `json:"sev"`
	Data      map[string]any `json:"data"`
}

type pending struct {
	ts   time.Time
	typ  string
	sev  int
	data map[string]any
	ord  int
}

type boot struct {
	at time.Time
	id string
}

type usageAcc struct{ rx, tx int64 }

// Options configure a generator.
type Options struct {
	Start        time.Time // generation starts here
	Seed         int64
	Rate         float64 // multiplier of traffic and notification volumes
	AgentVersion string
	SeqBase      int64
}

// Generator produces events chronologically.
type Generator struct {
	rng     *rand.Rand
	seed    int64
	loc     *time.Location
	rate    float64
	version string
	cur     time.Time
	seq     int64
	ord     int
	boots   []boot
	pend    []pending

	battery    float64
	plugged    string
	powerSave  bool
	lastBatt   int
	screenOn   bool
	screenOff  time.Time
	fg         *app
	fgUntil    time.Time
	nextFix    time.Time
	nextHB     time.Time
	nextScan   time.Time
	nextCell   time.Time
	cellSalt   int
	segKey     string
	lastSeg    segment
	btOn       bool
	lastDaily  string
	usageHour  time.Time
	usage      map[string]*usageAcc
	posture    map[string]any
	dropped    int
	mockFixAt  time.Time
	uploadedAt time.Time
	laters     []laterFn
	floor      time.Time
}

// New returns a generator starting at opts.Start.
func New(opts Options) *Generator {
	loc, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		loc = time.UTC
	}
	rate := opts.Rate
	if rate <= 0 {
		rate = 1
	}
	if opts.AgentVersion == "" {
		opts.AgentVersion = "1.0.0-sim"
	}
	start := opts.Start.UTC().Truncate(time.Millisecond)
	g := &Generator{
		rng: rand.New(rand.NewSource(opts.Seed)), seed: opts.Seed, loc: loc, rate: rate, version: opts.AgentVersion,
		cur: start, seq: opts.SeqBase, battery: 64, plugged: "none", usage: map[string]*usageAcc{},
	}
	g.lastBatt = int(g.battery)
	// The phone has been up for a few days.
	g.boots = []boot{{at: start.Add(-time.Duration(2+g.rng.Intn(5))*24*time.Hour - time.Duration(g.rng.Intn(3600))*time.Second), id: g.newBootID()}}
	g.nextHB = start.Add(time.Duration(g.rng.Intn(900)) * time.Second)
	g.nextFix = start.Add(time.Duration(g.rng.Intn(60)) * time.Second)
	g.nextScan = start.Add(10 * time.Minute)
	g.usageHour = start.Truncate(time.Hour)
	g.uploadedAt = start
	g.posture = basePosture(start)
	g.startup(start, "boot_completed")
	g.lastDaily = start.In(loc).Format("2006-01-02")
	if start.In(loc).Hour() < 3 { // daily jobs of today have not run yet
		g.lastDaily = start.In(loc).AddDate(0, 0, -1).Format("2006-01-02")
	}
	return g
}

func (g *Generator) newBootID() string {
	return fmt.Sprintf("%08x-%04x-%04x-%04x-%012x", g.rng.Uint32(), g.rng.Intn(1<<16), 0x4000|g.rng.Intn(1<<12),
		0x8000|g.rng.Intn(1<<14), g.rng.Int63n(1<<48))
}

// emit schedules an event.
func (g *Generator) emit(ts time.Time, typ string, sev int, data map[string]any) {
	if ts.Before(g.floor) { // never emit before what has already been returned
		ts = g.floor
	}
	g.ord++
	g.pend = append(g.pend, pending{ts: ts.UTC().Truncate(time.Millisecond), typ: typ, sev: sev, data: data, ord: g.ord})
}

// Advance generates events up to `to` and returns those with ts < to, in order.
func (g *Generator) Advance(to time.Time) []Event {
	for g.cur.Before(to) {
		next := g.cur.Add(time.Minute)
		if next.After(to) {
			next = to
		}
		g.step(g.cur, next)
		g.cur = next
	}
	return g.flush(to)
}

// Now returns the generation cursor.
func (g *Generator) Now() time.Time { return g.cur }

func (g *Generator) flush(to time.Time) []Event {
	sort.SliceStable(g.pend, func(i, j int) bool {
		if !g.pend[i].ts.Equal(g.pend[j].ts) {
			return g.pend[i].ts.Before(g.pend[j].ts)
		}
		return g.pend[i].ord < g.pend[j].ord
	})
	n := sort.Search(len(g.pend), func(i int) bool { return !g.pend[i].ts.Before(to) })
	out := make([]Event, 0, n)
	for _, p := range g.pend[:n] {
		g.seq++
		b := g.bootAt(p.ts)
		out = append(out, Event{
			ID: NewULID(p.ts, g.rng), TS: p.ts.Format("2006-01-02T15:04:05.000Z07:00"), Seq: g.seq, BootID: b.id,
			ElapsedMS: p.ts.Sub(b.at).Milliseconds(), Type: p.typ, Sev: p.sev, Data: p.data,
		})
	}
	g.pend = append(g.pend[:0], g.pend[n:]...)
	g.floor = to
	return out
}

func (g *Generator) bootAt(ts time.Time) boot {
	b := g.boots[0]
	for _, x := range g.boots {
		if !x.at.After(ts) {
			b = x
		}
	}
	return b
}

func (g *Generator) jitter(t time.Time, max time.Duration) time.Time {
	if max <= 0 {
		return t
	}
	return t.Add(time.Duration(g.rng.Int63n(int64(max))))
}

func (g *Generator) poisson(lambda float64) int {
	if lambda <= 0 {
		return 0
	}
	if lambda > 30 {
		n := int(math.Round(lambda + math.Sqrt(lambda)*g.rng.NormFloat64()))
		return max(n, 0)
	}
	l, k, p := math.Exp(-lambda), 0, 1.0
	for {
		p *= g.rng.Float64()
		if p <= l {
			return k
		}
		k++
	}
}

func (g *Generator) step(t0, t1 time.Time) {
	for len(g.laters) > 0 && g.laters[0].at.Before(t1) {
		l := g.laters[0]
		g.laters = g.laters[1:]
		l.fn(l.at)
	}
	lt := t0.In(g.loc)
	seg, _ := segmentAt(lt)
	key := fmt.Sprintf("%s/%d/%v", lt.Format("2006-01-02"), seg.start, seg.mode)
	if key != g.segKey {
		if g.segKey != "" {
			g.transition(g.lastSeg, seg, t0)
		}
		g.segKey, g.lastSeg = key, seg
	}

	// Daily jobs at 03:00 local time.
	if day := lt.Format("2006-01-02"); day != g.lastDaily && lt.Hour() >= 3 {
		g.lastDaily = day
		g.daily(g.jitter(t0, 50*time.Second), true)
	}
	for g.nextHB.Before(t1) {
		g.heartbeat(g.nextHB)
		g.nextHB = g.nextHB.Add(15 * time.Minute)
	}
	for g.nextFix.Before(t1) {
		g.fix(g.nextFix)
		g.nextFix = g.nextFix.Add(g.fixInterval(g.nextFix))
	}
	if seg.mode != modeStill && !g.nextCell.After(t0) {
		g.cellSalt++
		g.cellChange(g.jitter(t0, time.Minute))
		g.nextCell = t0.Add(time.Duration(90+g.rng.Intn(150)) * time.Second)
	}
	g.screen(t0, t1, seg)
	g.traffic(t0, t1)
	g.notifications(t0, t1)
	g.batteryStep(t0, t1)
	if g.screenOn && g.nextScan.Before(t1) {
		g.wifiScan(g.nextScan, seg)
		g.nextScan = g.nextScan.Add(10 * time.Minute)
	} else if !g.screenOn && g.nextScan.Before(t1) {
		g.nextScan = t1.Add(time.Minute)
	}
	for h := g.usageHour.Add(time.Hour); !h.After(t1); h = h.Add(time.Hour) {
		g.netUsage(g.usageHour, h)
		g.usageHour = h
	}
}

// --- location -------------------------------------------------------------

func (g *Generator) fixInterval(t time.Time) time.Duration {
	seg, _ := segmentAt(t.In(g.loc))
	switch seg.mode {
	case modeMetro:
		return time.Duration(150+g.rng.Intn(90)) * time.Second
	case modeWalk, modeBike:
		return time.Duration(25+g.rng.Intn(20)) * time.Second
	}
	return time.Duration(240+g.rng.Intn(120)) * time.Second
}

func (g *Generator) position(t time.Time) (latLon, float64, float64, string, float64) {
	seg, frac := segmentAt(t.In(g.loc))
	switch seg.mode {
	case modeStill:
		p := offset(seg.at, g.rng.NormFloat64()*8, g.rng.NormFloat64()*8)
		prov := "fused"
		acc := 8 + g.rng.Float64()*20
		if g.rng.Intn(4) == 0 {
			prov, acc = "network", 20+g.rng.Float64()*40
		}
		return p, 0, 0, prov, acc
	default:
		p, brg := along(seg.route, frac)
		dur := (seg.end - seg.start).Seconds()
		speed := routeLength(seg.route) / dur * (0.85 + 0.3*g.rng.Float64())
		if seg.mode == modeMetro {
			return offset(p, g.rng.NormFloat64()*60, g.rng.NormFloat64()*60), speed, brg, "network", 50 + g.rng.Float64()*100
		}
		return offset(p, g.rng.NormFloat64()*4, g.rng.NormFloat64()*4), speed, brg, "gps", 3 + g.rng.Float64()*9
	}
}

func (g *Generator) fix(t time.Time) {
	p, speed, brg, prov, acc := g.position(t)
	data := map[string]any{
		"lat": round(p.lat, 6), "lon": round(p.lon, 6), "acc_m": round(acc, 1), "alt_m": round(35+g.rng.Float64()*25, 1),
		"speed_mps": round(speed, 2), "bearing_deg": round(brg, 1), "provider": prov, "mock": false,
		"fix_ts": t.Add(-time.Duration(g.rng.Intn(800)) * time.Millisecond).Format("2006-01-02T15:04:05.000Z07:00"),
	}
	sev := 0
	if !g.mockFixAt.IsZero() && !t.Before(g.mockFixAt) {
		// A mock location provider was briefly used (scenario).
		g.mockFixAt = time.Time{}
		data["mock"] = true
		data["provider"] = "gps"
		data["lat"], data["lon"] = 48.80490, 2.12040 // Versailles: spoofed but plausible
		sev = 2
	}
	g.emit(t, "location.fix", sev, data)
}

// --- connectivity ---------------------------------------------------------

func placeWifi(place string) *wifiNet {
	switch place {
	case "home":
		return &wifiHome
	case "office":
		return &wifiOffice
	}
	return nil
}

func (g *Generator) transition(prev, next segment, t time.Time) {
	if w := placeWifi(prev.place); w != nil && placeWifi(next.place) != w {
		g.emit(t, "net.wifi", 0, map[string]any{"event": "disconnected", "ssid": w.ssid, "bssid": w.bssid})
		g.connectivity(g.jitter(t.Add(time.Second), time.Second), nil)
		g.cellChange(t.Add(2 * time.Second))
		if !g.btOn {
			g.btOn = true
			g.emit(t.Add(40*time.Second), "net.bluetooth", 0, map[string]any{"event": "connected", "enabled": true,
				"name": "Galaxy Buds2 Pro", "address": "8c:79:f5:1e:42:a7", "type": "audio"})
			g.emit(t.Add(41*time.Second), "security.log", 0, map[string]any{"tag": "bluetooth_connection", "level": "info",
				"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"address": "8c:79:f5:1e:42:a7", "connected": true, "reason": ""}})
		}
	}
	if w := placeWifi(next.place); w != nil && placeWifi(prev.place) != w {
		ts := t.Add(time.Duration(20+g.rng.Intn(60)) * time.Second)
		g.emit(ts, "net.wifi", 0, map[string]any{"event": "connected", "ssid": w.ssid, "bssid": w.bssid,
			"rssi": -45 - g.rng.Intn(20), "freq_mhz": w.freq, "security": w.security, "standard": w.standard})
		g.emit(ts.Add(300*time.Millisecond), "security.log", 0, map[string]any{"tag": "wifi_connection", "level": "info",
			"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"bssid": w.bssid, "event_type": "connect", "reason": ""}})
		g.connectivity(ts.Add(2*time.Second), w)
		if g.btOn {
			g.btOn = false
			g.emit(ts.Add(5*time.Second), "net.bluetooth", 0, map[string]any{"event": "disconnected", "enabled": true,
				"name": "Galaxy Buds2 Pro", "address": "8c:79:f5:1e:42:a7", "type": "audio"})
		}
	}
	if next.mode == modeMetro {
		g.cellChange(t.Add(30 * time.Second))
	}
}

func (g *Generator) connectivity(t time.Time, w *wifiNet) {
	d := map[string]any{"validated": true, "vpn": false, "private_dns_active": true, "private_dns_server": "dns.vigie.example"}
	if w != nil {
		d["transports"] = []any{"wifi"}
		d["metered"] = false
		d["interface"] = "wlan0"
		d["dns_servers"] = []any{"192.168.1.1", "fe80::1%wlan0"}
	} else {
		d["transports"] = []any{"cellular"}
		d["metered"] = true
		d["interface"] = "rmnet_data1"
		d["dns_servers"] = []any{"80.10.246.2", "80.10.246.129"}
	}
	g.emit(t, "net.connectivity", 0, d)
}

func (g *Generator) cellChange(t time.Time) {
	p, _, _, _, _ := g.position(t)
	g.emit(t, "net.cell", 0, cellFor(p, g.cellSalt))
}

func (g *Generator) wifiScan(t time.Time, seg segment) {
	place := seg.place
	if seg.mode != modeStill {
		place = ""
	}
	nets := neighborAPs[place]
	var aps []any
	for _, n := range nets {
		aps = append(aps, map[string]any{"ssid": n.ssid, "bssid": n.bssid, "rssi": -40 - g.rng.Intn(50), "freq_mhz": n.freq, "security": n.security})
	}
	for i := 0; i < 3+g.rng.Intn(6); i++ { // passing networks
		aps = append(aps, map[string]any{"ssid": fmt.Sprintf("Livebox-%04X", g.rng.Intn(1<<16)),
			"bssid": fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", 0xa4, 0x3e, 0x51, g.rng.Intn(256), g.rng.Intn(256), g.rng.Intn(256)),
			"rssi":  -70 - g.rng.Intn(25), "freq_mhz": []int{2412, 2437, 2462, 5180, 5500}[g.rng.Intn(5)], "security": "WPA2-PSK"})
	}
	g.emit(t, "net.wifi_scan", 0, map[string]any{"aps": aps})
}

// --- screen, apps, notifications -----------------------------------------

func (g *Generator) pickApp() *app {
	total := 0
	for _, a := range apps {
		total += a.fgWeight
	}
	n := g.rng.Intn(total)
	for i := range apps {
		n -= apps[i].fgWeight
		if n < 0 {
			return &apps[i]
		}
	}
	return &apps[0]
}

func (g *Generator) screen(t0, t1 time.Time, seg segment) {
	if g.screenOn {
		for g.fgUntil.Before(t1) && g.fgUntil.Before(g.screenOff) {
			at := g.fgUntil
			g.foreground(at, g.fg, "paused")
			g.fg = g.pickApp()
			g.foreground(at.Add(400*time.Millisecond), g.fg, "resumed")
			g.fgUntil = at.Add(time.Duration(30+g.rng.Intn(240)) * time.Second)
		}
		if g.screenOff.Before(t1) {
			at := g.screenOff
			g.foreground(at, g.fg, "paused")
			g.emit(at.Add(200*time.Millisecond), "device.screen", 0, map[string]any{"state": "off"})
			g.emit(at.Add(300*time.Millisecond), "security.log", 0, map[string]any{"tag": "keyguard_secured", "level": "info",
				"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{}})
			g.screenOn, g.fg = false, nil
		}
		return
	}
	meanGap := 14.0
	switch {
	case !awake(t0.In(g.loc)):
		meanGap = 240
	case seg.mode != modeStill:
		meanGap = 5
	case seg.place == "office":
		meanGap = 22
	}
	dt := t1.Sub(t0).Minutes()
	if g.rng.Float64() >= dt/meanGap {
		return
	}
	at := g.jitter(t0, t1.Sub(t0))
	dur := time.Duration((30 + g.rng.ExpFloat64()*240) * float64(time.Second))
	if !awake(at.In(g.loc)) {
		dur = time.Duration(10+g.rng.Intn(50)) * time.Second
	}
	g.screenOn = true
	g.screenOff = at.Add(dur)
	g.emit(at, "device.screen", 0, map[string]any{"state": "on"})
	unlock := at.Add(time.Duration(1500+g.rng.Intn(2500)) * time.Millisecond)
	g.emit(unlock, "security.log", 0, map[string]any{"tag": "keyguard_dismiss_auth_attempt", "level": "info",
		"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"success": true, "method_strength": 1}})
	g.emit(unlock.Add(50*time.Millisecond), "security.keyguard", 0, map[string]any{"event": "unlock_succeeded", "failed_attempts": 0})
	g.emit(unlock.Add(80*time.Millisecond), "device.screen", 0, map[string]any{"state": "unlocked"})
	g.emit(unlock.Add(90*time.Millisecond), "security.log", 0, map[string]any{"tag": "keyguard_dismissed", "level": "info",
		"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{}})
	g.fg = g.pickApp()
	g.foreground(unlock.Add(time.Second), g.fg, "resumed")
	g.fgUntil = unlock.Add(time.Duration(30+g.rng.Intn(240)) * time.Second)
}

func (g *Generator) foreground(t time.Time, a *app, event string) {
	if a == nil {
		return
	}
	g.emit(t, "app.foreground", 0, map[string]any{"package": a.pkg, "class": a.pkg + ".MainActivity", "event": event})
	if event == "resumed" && g.rng.Intn(3) == 0 {
		g.emit(t, "security.log", 0, map[string]any{"tag": "app_process_start", "level": "info",
			"log_id": g.rng.Intn(1 << 20), "fields": map[string]any{"process": a.pkg, "start_time": t.UnixMilli(), "uid": a.uid,
				"pid": 4000 + g.rng.Intn(28000), "seinfo": "default:targetSdkVersion=35:complete", "apk_hash": sha256Hex("apk:" + a.pkg + a.version)}})
	}
}

func (g *Generator) notifications(t0, t1 time.Time) {
	if !awake(t0.In(g.loc)) {
		return
	}
	n := g.poisson(9 * t1.Sub(t0).Hours() * g.rate)
	var pool []*app
	for i := range apps {
		if apps[i].notifies {
			pool = append(pool, &apps[i])
		}
	}
	for range n {
		a := pool[g.rng.Intn(len(pool))]
		at := g.jitter(t0, t1.Sub(t0))
		cat, ch := "msg", "messages"
		switch a.pkg {
		case "com.samsung.android.email.provider":
			cat, ch = "email", "new_mail"
		case "fr.lemonde.editorial":
			cat, ch = "recommendation", "alertes_info"
		case "fr.creditagricole.androidapp":
			cat, ch = "status", "operations"
		case "com.strava":
			cat, ch = "social", "kudos"
		case "com.instagram.android":
			cat, ch = "social", "ig_direct"
		}
		d := map[string]any{"package": a.pkg, "event": "posted", "category": cat, "channel": ch, "ongoing": false}
		g.emit(at, "app.notification", 0, d)
		g.emit(at.Add(time.Duration(20+g.rng.Intn(3600))*time.Second), "app.notification", 0,
			map[string]any{"package": a.pkg, "event": "removed", "category": cat, "channel": ch, "ongoing": false})
		if a.pkg == "com.whatsapp" || a.pkg == "org.thoughtcrime.securesms" {
			g.dns(a, at.Add(300*time.Millisecond))
		}
	}
}

// --- network --------------------------------------------------------------

func (g *Generator) traffic(t0, t1 time.Time) {
	dt := t1.Sub(t0)
	asleep := !awake(t0.In(g.loc))
	for i := range apps {
		a := &apps[i]
		lambda := 1.5 * a.bgPerHour * dt.Hours() * g.rate
		if asleep && !a.system {
			lambda /= 3
		}
		for range g.poisson(lambda) {
			g.dns(a, g.jitter(t0, dt))
		}
	}
	if g.screenOn && g.fg != nil && len(g.fg.hosts) > 0 {
		end := t1
		if g.screenOff.Before(end) {
			end = g.screenOff
		}
		if end.After(t0) {
			for range g.poisson(20 * end.Sub(t0).Minutes() * g.rate) {
				g.dns(g.fg, g.jitter(t0, end.Sub(t0)))
			}
		}
	}
}

func (g *Generator) dns(a *app, t time.Time) {
	if len(a.hosts) == 0 {
		return
	}
	host := a.hosts[g.rng.Intn(len(a.hosts))]
	addrs := addressesFor(host)
	list := make([]any, len(addrs))
	for i, x := range addrs {
		list[i] = x
	}
	g.emit(t, "net.dns", 0, map[string]any{"package": a.pkg, "uid": a.uid, "hostname": host, "addresses": list, "address_count": len(addrs)})
	if g.rng.Float64() < 0.8 {
		port := 443
		switch {
		case host == "mtalk.google.com":
			port = 5228
		case host == "imap.fastmail.com":
			port = 993
		case host == "smtp.fastmail.com":
			port = 465
		case g.rng.Intn(40) == 0:
			port = 80
		}
		g.emit(t.Add(time.Duration(5+g.rng.Intn(400))*time.Millisecond), "net.connect", 0,
			map[string]any{"package": a.pkg, "uid": a.uid, "ip": addrs[g.rng.Intn(len(addrs))], "port": port})
		u := g.usage[a.pkg]
		if u == nil {
			u = &usageAcc{}
			g.usage[a.pkg] = u
		}
		mult := int64(1)
		if a.pkg == "com.google.android.youtube" || a.pkg == "com.spotify.music" || a.pkg == "com.instagram.android" {
			mult = 12
		}
		u.rx += (2000 + g.rng.Int63n(150000)) * mult
		u.tx += 500 + g.rng.Int63n(12000)
	}
}

func (g *Generator) netUsage(from, to time.Time) {
	transport := "cellular"
	if seg, _ := segmentAt(from.In(g.loc)); placeWifi(seg.place) != nil {
		transport = "wifi"
	}
	var list []any
	pkgs := make([]string, 0, len(g.usage))
	for p := range g.usage {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	for _, p := range pkgs {
		u := g.usage[p]
		a := appByPkg(p)
		list = append(list, map[string]any{"package": p, "uid": a.uid, "rx_bytes": u.rx, "tx_bytes": u.tx, "transport": transport})
	}
	g.usage = map[string]*usageAcc{}
	g.emit(to.Add(time.Duration(g.rng.Intn(20))*time.Second), "net.usage", 0, map[string]any{
		"from": from.Format(time.RFC3339), "to": to.Format(time.RFC3339), "apps": list})
}

// --- battery and heartbeat ------------------------------------------------

func (g *Generator) charging(t time.Time) bool {
	lt := t.In(g.loc)
	d := sinceMidnight(lt)
	if isWeekend(lt) {
		return d >= hm(0, 40) && d < hm(9, 30)
	}
	return d >= hm(23, 40) || d < hm(7, 10)
}

func (g *Generator) batteryStep(t0, t1 time.Time) {
	h := t1.Sub(t0).Hours()
	ch := g.charging(t0)
	newPlug := "none"
	if ch {
		newPlug = "ac"
	}
	switch {
	case ch:
		g.battery = math.Min(100, g.battery+28*h)
	case g.screenOn:
		g.battery -= 11 * h
	case awake(t0.In(g.loc)):
		g.battery -= 1.8 * h
	default:
		g.battery -= 0.7 * h
	}
	g.battery = math.Max(3, g.battery)
	pct := int(g.battery)
	if newPlug != g.plugged || pct/5 != g.lastBatt/5 {
		status := "discharging"
		if newPlug != "none" {
			status = "charging"
			if pct >= 100 {
				status = "full"
			}
		}
		g.plugged = newPlug
		g.lastBatt = pct
		g.emit(t0, "device.battery", 0, map[string]any{"pct": pct, "plugged": newPlug, "status": status,
			"temperature_c": round(27+g.rng.Float64()*8, 1), "health": "good"})
	}
	if !g.powerSave && pct < 15 && !ch {
		g.powerSave = true
		g.emit(t0.Add(time.Second), "device.power_save", 0, map[string]any{"enabled": true})
	} else if g.powerSave && ch && pct > 30 {
		g.powerSave = false
		g.emit(t0.Add(time.Second), "device.power_save", 0, map[string]any{"enabled": false})
	}
}

var collectors = map[string]any{
	"location": "running", "screen": "running", "battery": "running", "connectivity": "running", "wifi": "running",
	"wifi_scan": "running", "cell": "running", "network_log": "running", "network_usage": "running", "bluetooth": "running",
	"ble_tracker": "running", "app_inventory": "running", "app_usage": "running", "notifications": "running",
	"notification_content": "disabled", "sensors": "running", "security_log": "running", "posture": "running",
	"cell_security": "unavailable",
}

func (g *Generator) heartbeat(t time.Time) {
	b := g.bootAt(t)
	g.uploadedAt = t.Add(-time.Duration(20+g.rng.Intn(280)) * time.Second)
	depth := g.rng.Intn(60)
	g.emit(t, "agent.heartbeat", 0, map[string]any{
		"battery_pct": int(g.battery), "charging": g.plugged != "none", "uptime_ms": t.Sub(b.at).Milliseconds(),
		"queue_depth": depth, "queue_bytes": depth * (300 + g.rng.Intn(500)), "dropped_total": g.dropped,
		"device_owner": true, "collectors": collectors, "last_upload_ts": g.uploadedAt.Format("2006-01-02T15:04:05.000Z07:00"),
	})
}

func round(f float64, n int) float64 {
	p := math.Pow(10, float64(n))
	return math.Round(f*p) / p
}
