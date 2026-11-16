package detect

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

// Engine evaluates the detections periodically. It never scans the events table: each run takes the hours
// marked by the ingestion (detect_dirty: an hour whose aggregates changed, late batches included), reads the
// hourly aggregates of those hours and of their days, and stores each finding once (store.AddDetections
// skips a finding already stored for the same device, type, subject and window). Reads go through the
// read-only pool (WAL: they never block the ingestion); writes are one short transaction per device and
// round. A run stops after its time budget; what remains is evaluated at the next run.
type Engine struct {
	st        *store.Store
	t         Thresholds
	res       *Resolvers
	clients   map[string][]string
	threats   bool
	log       *slog.Logger
	publish   func([]store.StoredEvent)
	now       func() time.Time
	batch     int
	budget    time.Duration
	retention time.Duration
}

// Options configure an Engine.
type Options struct {
	// AdGuardClients maps a device to its AdGuard Home clients (VIGIE_ADGUARD_CLIENTS; none: the whole log).
	AdGuardClients map[string][]string
	// ThreatLists is false when no list of category "threat" is declared: detect.threat_domain stays silent.
	ThreatLists bool
	Log         *slog.Logger
	// Publish hands the events of new findings to the exporter and the console stream.
	Publish func([]store.StoredEvent)
	Now     func() time.Time
	// Batch is the number of dirty hours read per round (default 256), Budget the time a run may take
	// (default 20 s).
	Batch  int
	Budget time.Duration
	// Retention: hours older than this are not evaluated (their data is being purged).
	Retention time.Duration
}

// NewEngine returns an engine.
func NewEngine(st *store.Store, t Thresholds, opt Options) *Engine {
	e := &Engine{st: st, t: t, res: DefaultResolvers(), clients: opt.AdGuardClients, threats: opt.ThreatLists, log: opt.Log,
		publish: opt.Publish, now: opt.Now, batch: opt.Batch, budget: opt.Budget, retention: opt.Retention}
	if e.log == nil {
		e.log = slog.New(slog.NewTextHandler(nopWriter{}, nil))
	}
	if e.now == nil {
		e.now = time.Now
	}
	if e.batch <= 0 {
		e.batch = 256
	}
	if e.budget <= 0 {
		e.budget = 20 * time.Second
	}
	if e.publish == nil {
		e.publish = func([]store.StoredEvent) {}
	}
	return e
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

// Run evaluates the detections every interval until ctx is canceled.
func (e *Engine) Run(ctx context.Context, interval time.Duration) {
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		st, err := e.RunOnce(ctx)
		switch {
		case err != nil && !errors.Is(err, context.Canceled):
			e.log.Error("détections : évaluation en échec (nouvel essai au prochain passage)", "err", err)
		case st.Hours > 0:
			e.log.Debug("détections : passage", "hours", st.Hours, "findings", st.Findings, "ms", st.Duration.Milliseconds(), "remaining", st.Remaining)
		}
		timer.Reset(interval)
	}
}

// Stats summarize a run.
type Stats struct {
	Rounds    int
	Hours     int // dirty hours evaluated
	Findings  int // new findings stored
	Remaining bool
	Duration  time.Duration
}

// RunOnce evaluates the dirty hours until none is left or the time budget is spent.
func (e *Engine) RunOnce(ctx context.Context) (Stats, error) {
	start := time.Now()
	var st Stats
	defer func() { st.Duration = time.Since(start) }()
	for {
		if err := ctx.Err(); err != nil {
			return st, err
		}
		if time.Since(start) > e.budget {
			st.Remaining = true
			return st, nil
		}
		hours, err := e.st.DirtyHours(ctx, e.batch)
		if err != nil {
			return st, err
		}
		if len(hours) == 0 {
			return st, nil
		}
		st.Rounds++
		n, err := e.round(ctx, hours)
		st.Findings += n
		if err != nil {
			return st, err
		}
		if err := e.st.ClearDirty(ctx, hours); err != nil {
			return st, err
		}
		st.Hours += len(hours)
	}
}

func (e *Engine) round(ctx context.Context, hours []store.DirtyHour) (int, error) {
	byDev := map[string][]int64{}
	var devs []string
	for _, h := range hours {
		if _, ok := byDev[h.DeviceID]; !ok {
			devs = append(devs, h.DeviceID)
		}
		byDev[h.DeviceID] = append(byDev[h.DeviceID], h.HourMS)
	}
	total := 0
	for _, dev := range devs {
		findings, err := e.evaluate(ctx, dev, byDev[dev])
		if err != nil {
			return total, err
		}
		if len(findings) == 0 {
			continue
		}
		ds := make([]store.Detection, 0, len(findings))
		for _, f := range findings {
			ds = append(ds, store.Detection{DeviceID: dev, Type: f.Type, Subject: f.Subject, WindowFromMS: f.FromMS, WindowToMS: f.ToMS,
				Package: f.Package, Label: f.Label, Sev: f.Sev, Summary: f.Summary, Evidence: f.Evidence})
		}
		evs, err := e.st.AddDetections(ctx, ds, e.now())
		if err != nil {
			return total, err
		}
		total += len(evs)
		for _, ev := range evs {
			var d struct {
				Package string `json:"package"`
			}
			_ = json.Unmarshal(ev.Data, &d)
			e.log.Info("détection", "type", ev.Type, "device_id", dev, "package", d.Package, "sev", ev.Sev)
		}
		e.publish(evs)
	}
	return total, nil
}

// deviceCtx is what the detections of one device need besides the aggregates.
type deviceCtx struct {
	labels   Labels
	system   map[string]bool
	roles    map[string]string // role -> latest holder
	firstUse int64             // first hour of net.usage (-1: none)
}

func (e *Engine) deviceContext(ctx context.Context, dev string) (*deviceCtx, error) {
	dc := &deviceCtx{labels: Labels{}, system: map[string]bool{}, roles: map[string]string{}, firstUse: -1}
	snap, err := e.st.LatestApps(ctx, dev)
	if err != nil {
		return nil, err
	}
	for _, a := range snap.Apps {
		m, ok := a.(map[string]any)
		if !ok {
			continue
		}
		p, _ := m["package"].(string)
		if p == "" {
			continue
		}
		if l, _ := m["label"].(string); l != "" {
			dc.labels[p] = l
		}
		if s, _ := m["system"].(bool); s {
			dc.system[p] = true
		}
	}
	risks, err := e.st.AppLatest(ctx, dev, store.AppLatestRisk)
	if err != nil {
		return nil, err
	}
	for p, ev := range risks {
		if l, _ := model.Str(decodeData(ev.Data), "label"); l != "" && dc.labels[p] == "" {
			dc.labels[p] = l
		}
	}
	// Default applications: the latest app.special_access (default_apps), then the latest app.role of each
	// role, which is more recent or more precise.
	if sa, err := e.st.EventsOfType(ctx, dev, "app.special_access", 0, 1<<62, 1); err != nil {
		return nil, err
	} else if len(sa) == 1 {
		if def, ok := decodeData(sa[0].Data)["default_apps"].(map[string]any); ok {
			for role, v := range def {
				if p, ok := v.(string); ok && p != "" {
					dc.roles[role] = p
				}
			}
		}
	}
	roles, err := e.st.AppLatest(ctx, dev, store.AppLatestRole)
	if err != nil {
		return nil, err
	}
	for role, ev := range roles {
		if p, _ := model.Str(decodeData(ev.Data), "new"); p != "" {
			dc.roles[role] = p
		} else {
			delete(dc.roles, role)
		}
	}
	if h, ok, err := e.st.FirstUsageHour(ctx, dev); err != nil {
		return nil, err
	} else if ok {
		dc.firstUse = h
	}
	return dc, nil
}

// roleHolders returns the applications that held a role during [from, to): the latest holder and those
// named (old or new) by the app.role events of the period.
func (e *Engine) roleHolders(ctx context.Context, dev string, dc *deviceCtx, from, to int64, roles ...string) (map[string]bool, bool, error) {
	out := map[string]bool{}
	known := false
	want := map[string]bool{}
	for _, r := range roles {
		want[r] = true
		if p := dc.roles[r]; p != "" {
			out[p], known = true, true
		}
	}
	evs, err := e.st.EventsOfType(ctx, dev, "app.role", from, to-1, 1000)
	if err != nil {
		return nil, false, err
	}
	for _, ev := range evs {
		d := decodeData(ev.Data)
		if r, _ := model.Str(d, "role"); !want[r] {
			continue
		}
		for _, k := range []string{"old", "new"} {
			if p, _ := model.Str(d, k); p != "" {
				out[p], known = true, true
			}
		}
	}
	return out, known, nil
}

func dayOf(ms int64) int64 { return ms - mod(ms, dayMS) }

func mod(a, b int64) int64 {
	m := a % b
	if m < 0 {
		m += b
	}
	return m
}

func (e *Engine) evaluate(ctx context.Context, dev string, hours []int64) ([]Finding, error) {
	dc, err := e.deviceContext(ctx, dev)
	if err != nil {
		return nil, err
	}
	var cutoff int64
	if e.retention > 0 {
		cutoff = e.now().Add(-e.retention).UnixMilli()
	}
	var out []Finding
	days := map[int64]bool{}
	sort.Slice(hours, func(i, j int) bool { return hours[i] < hours[j] })
	for _, h := range hours {
		if h+hourMS < cutoff {
			continue
		}
		days[dayOf(h)] = true
		if e.t.Enabled(TypeUploadSpike) {
			f, err := e.uploadSpike(ctx, dev, dc, h)
			if err != nil {
				return nil, err
			}
			out = append(out, f...)
		}
		if e.t.Enabled(TypeFanout) {
			f, err := e.fanout(ctx, dev, dc, h)
			if err != nil {
				return nil, err
			}
			out = append(out, f...)
		}
	}
	dayList := make([]int64, 0, len(days))
	for d := range days {
		dayList = append(dayList, d)
	}
	sort.Slice(dayList, func(i, j int) bool { return dayList[i] < dayList[j] })
	for _, d := range dayList {
		for _, fn := range []func(context.Context, string, *deviceCtx, int64) ([]Finding, error){
			e.threatDomain, e.connectionsOfDay, e.opsOfDay, e.newApps,
		} {
			f, err := fn(ctx, dev, dc, d)
			if err != nil {
				return nil, err
			}
			out = append(out, f...)
		}
	}
	for i := range out {
		if out[i].Label == "" && dc.labels[out[i].Package] != "" {
			out[i].Label = dc.labels[out[i].Package]
		}
	}
	return out, nil
}

func (e *Engine) uploadSpike(ctx context.Context, dev string, dc *deviceCtx, h int64) ([]Finding, error) {
	tx, err := e.st.HourlyTx(ctx, dev, h)
	if err != nil {
		return nil, err
	}
	in := UploadInput{HourMS: h, Tx: tx, History: map[string][]int64{}, ScreenOnMinutes: -1, Labels: dc.labels,
		Learning: dc.firstUse < 0 || h-dc.firstUse < int64(e.t.UploadLearnDays)*dayMS}
	above := false
	for pkg, b := range tx {
		if b <= e.t.UploadFloorBytes {
			continue
		}
		above = true
		hist, err := e.st.TxHistory(ctx, dev, pkg, h-UploadHistory.Milliseconds(), h)
		if err != nil {
			return nil, err
		}
		in.History[pkg] = hist
	}
	if !above {
		return nil, nil
	}
	if in.ScreenOnMinutes, err = e.screenOnMinutes(ctx, dev, h); err != nil {
		return nil, err
	}
	return UploadSpike(in, e.t), nil
}

func (e *Engine) fanout(ctx context.Context, dev string, dc *deviceCtx, h int64) ([]Finding, error) {
	rows, err := e.st.ConnectDests(ctx, dev, h, h+hourMS)
	if err != nil {
		return nil, err
	}
	dests := Dests(rows)
	if MaxDistinct(dests) <= min(e.t.Fanout, e.t.FanoutScreenOff) {
		return nil, nil
	}
	screen, err := e.screenOnMinutes(ctx, dev, h)
	if err != nil {
		return nil, err
	}
	return Fanout(h, dests, screen, dc.labels, e.t), nil
}

// screenOnMinutes returns the minutes of the hour [h, h+1h) spent screen on, from device.screen ("on" and
// "unlocked" are on): the state at the start of the hour is that of the last event before it (unknown: on,
// the cautious choice for detect.fanout). It returns -1 when the device never reported its screen.
func (e *Engine) screenOnMinutes(ctx context.Context, dev string, h int64) (int, error) {
	in, err := e.st.EventsOfType(ctx, dev, "device.screen", h, h+hourMS-1, 2000)
	if err != nil {
		return -1, err
	}
	before, err := e.st.EventsOfType(ctx, dev, "device.screen", 0, h-1, 1)
	if err != nil {
		return -1, err
	}
	if len(in) == 0 && len(before) == 0 {
		return -1, nil
	}
	on := true
	if len(before) == 1 {
		on = screenOn(before[0].Data)
	}
	var total int64
	cur := h
	for i := len(in) - 1; i >= 0; i-- { // EventsOfType is newest first
		ev := in[i]
		if on {
			total += ev.TSms - cur
		}
		cur = ev.TSms
		on = screenOn(ev.Data)
	}
	if on {
		total += h + hourMS - cur
	}
	return int(total / 60000), nil
}

func screenOn(raw json.RawMessage) bool {
	s, _ := model.Str(decodeData(raw), "state")
	return s != "off"
}

func (e *Engine) threatDomain(ctx context.Context, dev string, dc *deviceCtx, d int64) ([]Finding, error) {
	if !e.t.Enabled(TypeThreatDomain) || !e.threats {
		return nil, nil
	}
	// AdGuard Home and the phone may disagree by a few minutes on the hour: one hour of margin on each side.
	blocks, err := e.st.ThreatBlocks(ctx, e.clients[dev], d-hourMS, d+dayMS+hourMS)
	if err != nil || len(blocks) == 0 {
		return nil, err
	}
	domains := make([]string, 0, len(blocks))
	for _, b := range blocks {
		domains = append(domains, b.Domain)
	}
	lookups, err := e.st.DNSLookupsOf(ctx, dev, domains, d, d+dayMS)
	if err != nil || len(lookups) == 0 {
		return nil, err
	}
	browsers, _, err := e.roleHolders(ctx, dev, dc, d, d+dayMS, "browser")
	if err != nil {
		return nil, err
	}
	return ThreatDomain(ThreatInput{DayMS: d, Blocks: blocks, Lookups: lookups, Browsers: browsers, Labels: dc.labels}), nil
}

func (e *Engine) connectionsOfDay(ctx context.Context, dev string, dc *deviceCtx, d int64) ([]Finding, error) {
	if !e.t.Enabled(TypeMailPorts) && !e.t.Enabled(TypeDNSBypass) {
		return nil, nil
	}
	rows, err := e.st.ConnectDests(ctx, dev, d, d+dayMS)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	dests := Dests(rows)
	var out []Finding
	if e.t.Enabled(TypeMailPorts) {
		out = append(out, MailPortsRule(d, dests, dc.labels, e.t)...)
	}
	if e.t.Enabled(TypeDNSBypass) {
		out = append(out, DNSBypass(d, dests, e.res, dc.labels, e.t)...)
	}
	return out, nil
}

func (e *Engine) opsOfDay(ctx context.Context, dev string, dc *deviceCtx, d int64) ([]Finding, error) {
	if !e.t.Enabled(TypeSMSAbuse) && !e.t.Enabled(TypeSensorBackground) {
		return nil, nil
	}
	uses, err := e.st.OpsUses(ctx, dev, d, d+dayMS)
	if err != nil || len(uses) == 0 {
		return nil, err // app.ops is experimental: no data, no finding, no error
	}
	in := OpsInput{DayMS: d, Uses: uses, System: dc.system, Labels: dc.labels}
	sms, known, err := e.roleHolders(ctx, dev, dc, d, d+dayMS, "sms")
	if err != nil {
		return nil, err
	}
	if known {
		in.SMSApps = sms
	}
	if in.SensorExempt, _, err = e.roleHolders(ctx, dev, dc, d, d+dayMS, "dialer", "assistant", "call_screening"); err != nil {
		return nil, err
	}
	var out []Finding
	if e.t.Enabled(TypeSMSAbuse) {
		out = append(out, SMSAbuse(in, e.t)...)
	}
	if e.t.Enabled(TypeSensorBackground) {
		out = append(out, SensorBackground(in, e.t)...)
	}
	return out, nil
}

// specialAccessKinds maps the lists of app.special_access to capabilities.
var specialAccessKinds = map[string]string{
	"accessibility_services": "accessibility", "notification_listeners": "notification_listener", "device_admins": "device_admin",
	"overlay_apps": "overlay", "unknown_sources_apps": "unknown_sources", "vpn_apps": "vpn",
}

const maxAppEvents = 5000

func (e *Engine) newApps(ctx context.Context, dev string, dc *deviceCtx, d int64) ([]Finding, error) {
	if !e.t.Enabled(TypeNewAppRisky) {
		return nil, nil
	}
	// An installation up to 24 h before the day, or capabilities up to 24 h after it.
	from, to := d-dayMS, d+2*dayMS
	installs, err := e.st.EventsOfType(ctx, dev, "app.installed", from, to, maxAppEvents)
	if err != nil || len(installs) == 0 {
		return nil, err
	}
	in := NewAppInput{Labels: dc.labels}
	for _, ev := range installs {
		m := decodeData(ev.Data)
		p, _ := model.Str(m, "package")
		inst, _ := model.Str(m, "installer")
		in.Installs = append(in.Installs, Install{Package: p, Installer: inst, TS: ev.TSms})
	}
	risks, err := e.st.EventsOfType(ctx, dev, "app.risk", from-hourMS, to+dayMS, maxAppEvents)
	if err != nil {
		return nil, err
	}
	for _, ev := range risks {
		m := decodeData(ev.Data)
		r := Risk{TS: ev.TSms}
		r.Package, _ = model.Str(m, "package")
		r.Label, _ = model.Str(m, "label")
		r.Level, _ = model.Str(m, "level")
		r.Score, _ = model.Int(m, "score")
		if b, ok := model.Bool(m, "from_store"); ok {
			r.FromStore = &b
		}
		if list, ok := m["reasons"].([]any); ok {
			for _, x := range list {
				if s, ok := x.(string); ok && len(r.Reasons) < 32 {
					r.Reasons = append(r.Reasons, s)
				}
			}
		}
		in.Risks = append(in.Risks, r)
	}
	perms, err := e.st.EventsOfType(ctx, dev, "app.permission_changed", from, to+dayMS, maxAppEvents)
	if err != nil {
		return nil, err
	}
	for _, ev := range perms {
		m := decodeData(ev.Data)
		if g, _ := model.Bool(m, "granted"); !g {
			continue
		}
		p, _ := model.Str(m, "package")
		perm, _ := model.Str(m, "permission")
		in.Caps = append(in.Caps, Capability{Package: p, Kind: "permission:" + perm[strings.LastIndexByte(perm, '.')+1:], TS: ev.TSms})
	}
	access, err := e.st.EventsOfType(ctx, dev, "app.special_access", from, to+dayMS, 200)
	if err != nil {
		return nil, err
	}
	for _, ev := range access {
		m := decodeData(ev.Data)
		for key, kind := range specialAccessKinds {
			list, _ := m[key].([]any)
			for _, x := range list {
				s, _ := x.(string)
				if p, _, _ := strings.Cut(s, "/"); p != "" {
					in.Caps = append(in.Caps, Capability{Package: p, Kind: kind, TS: ev.TSms})
				}
			}
		}
	}
	roles, err := e.st.EventsOfType(ctx, dev, "app.role", from, to+dayMS, 1000)
	if err != nil {
		return nil, err
	}
	for _, ev := range roles {
		m := decodeData(ev.Data)
		r, _ := model.Str(m, "role")
		p, _ := model.Str(m, "new")
		if r != "" && p != "" {
			in.Caps = append(in.Caps, Capability{Package: p, Kind: "role:" + r, TS: ev.TSms})
		}
	}
	return NewAppRisky(in), nil
}

func decodeData(raw json.RawMessage) map[string]any {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if dec.Decode(&m) != nil || m == nil {
		return map[string]any{}
	}
	return m
}
