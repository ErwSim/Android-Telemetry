package detect

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

var hour0 = time.Date(2026, 11, 10, 14, 0, 0, 0, time.UTC).UnixMilli()

func one(t *testing.T, fs []Finding, typ, pkg string) Finding {
	t.Helper()
	if len(fs) != 1 || fs[0].Type != typ || fs[0].Package != pkg {
		t.Fatalf("want one %s for %s, got %+v", typ, pkg, fs)
	}
	if fs[0].Summary == "" || fs[0].Evidence == nil || fs[0].ToMS <= fs[0].FromMS || fs[0].Subject == "" {
		t.Fatalf("incomplete finding %+v", fs[0])
	}
	return fs[0]
}

func none(t *testing.T, fs []Finding, why string) {
	t.Helper()
	if len(fs) != 0 {
		t.Fatalf("%s: unexpected %+v", why, fs)
	}
}

func TestEmbeddedLists(t *testing.T) {
	r := DefaultResolvers()
	if r.Len() < 50 {
		t.Fatalf("resolvers: %d", r.Len())
	}
	for addr, want := range map[string]string{"1.1.1.1": "Cloudflare DNS", "2001:4860:4860::8888": "Google Public DNS",
		"45.90.28.17": "NextDNS", "::ffff:9.9.9.9": "Quad9"} {
		if got, ok := r.Lookup(netip.MustParseAddr(addr)); !ok || got != want {
			t.Errorf("%s: %q %v", addr, got, ok)
		}
	}
	if _, ok := r.Lookup(netip.MustParseAddr("142.250.75.238")); ok {
		t.Error("an ordinary Google address is not a resolver")
	}
	if _, err := ParseResolvers("1.2.3.4\n"); err == nil {
		t.Error("line without a name accepted")
	}
	if _, err := ParseResolvers("pas-une-ip Nom\n"); err == nil {
		t.Error("bad address accepted")
	}
	d := Defaults()
	if !d.MailClients["com.google.android.gm"] || !d.MailClients["com.samsung.android.email.provider"] || d.MailClients["com.whatsapp"] {
		t.Fatal("mail clients")
	}
}

func TestParseEnv(t *testing.T) {
	env := map[string]string{
		"VIGIE_DETECT_DISABLE": "fanout, detect.mail_ports", "VIGIE_DETECT_UPLOAD_FLOOR_MB": "200", "VIGIE_DETECT_UPLOAD_FACTOR": "5.5",
		"VIGIE_DETECT_MAIL_CLIENTS": "org.example.mail", "VIGIE_DETECT_DNS_BYPASS_PORTS": "443,853,53", "VIGIE_DETECT_FANOUT": "50",
	}
	th, errs := ParseEnv(func(k string) string { return env[k] })
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	if th.Enabled(TypeFanout) || th.Enabled(TypeMailPorts) || !th.Enabled(TypeUploadSpike) || th.UploadFloorBytes != 200<<20 ||
		th.UploadFactor != 5.5 || !th.MailClients["org.example.mail"] || !th.MailClients["com.google.android.gm"] || !th.DNSBypassPorts[53] ||
		th.Fanout != 50 {
		t.Fatalf("%+v", th)
	}
	for k, v := range map[string]string{"VIGIE_DETECT_DISABLE": "fanot", "VIGIE_DETECT_FANOUT": "0", "VIGIE_DETECT_UPLOAD_FACTOR": "x",
		"VIGIE_DETECT_DNS_BYPASS_PORTS": "70000", "VIGIE_DETECT_MAIL_CLIENTS": "a;b", "VIGIE_DETECT_SMS_DAILY_MAX": "-1"} {
		if _, errs := ParseEnv(func(key string) string {
			if key == k {
				return v
			}
			return ""
		}); len(errs) != 1 {
			t.Errorf("%s=%s: %v", k, v, errs)
		}
	}
}

func TestUploadSpike(t *testing.T) {
	th := Defaults()
	floor := th.UploadFloorBytes
	steady := make([]int64, 200)
	for i := range steady {
		steady[i] = 2 << 20 // 2 MiB per active hour
	}
	in := func(tx int64, hist []int64, learning bool) UploadInput {
		return UploadInput{HourMS: hour0, Tx: map[string]int64{"com.gallery": tx, "com.small": 5 << 20},
			History: map[string][]int64{"com.gallery": hist}, Learning: learning, ScreenOnMinutes: 0}
	}
	f := one(t, UploadSpike(in(3*floor, steady, false), th), TypeUploadSpike, "com.gallery")
	if f.Evidence["median_bytes"] != int64(2<<20) || f.Evidence["learning"] != false || f.Evidence["threshold_bytes"] != floor ||
		!strings.Contains(f.Summary, "3 Gio") || !strings.Contains(f.Summary, "écran éteint") {
		t.Fatalf("%+v", f)
	}
	none(t, UploadSpike(in(floor, steady, false), th), "at the floor")
	// k × median above the floor: a heavy uploader is compared to itself.
	heavy := make([]int64, 100)
	for i := range heavy {
		heavy[i] = 400 << 20
	}
	none(t, UploadSpike(in(3999<<20, heavy, false), th), "just under 10 × median")
	one(t, UploadSpike(in(4001<<20, heavy, false), th), TypeUploadSpike, "com.gallery")
	// Learning (device history too short, or new application): the floor alone.
	f = one(t, UploadSpike(in(floor+1, heavy, true), th), TypeUploadSpike, "com.gallery")
	if f.Evidence["learning"] != true || f.Evidence["median_bytes"] != nil {
		t.Fatalf("learning %+v", f)
	}
	one(t, UploadSpike(in(floor+1, heavy[:UploadMinActiveHrs-1], false), th), TypeUploadSpike, "com.gallery")
	none(t, UploadSpike(UploadInput{HourMS: hour0}, th), "no data")
}

func dests(pkg string, n, port int, base string) []Dest {
	out := make([]Dest, n)
	for i := range n {
		out[i] = Dest{Package: pkg, Addr: netip.MustParseAddr(fmt.Sprintf("%s.%d.%d", base, i/250, 1+i%250)), Port: port, Count: 2}
	}
	return out
}

func TestFanout(t *testing.T) {
	th := Defaults()
	ds := append(dests("com.proxy.sdk", 101, 443, "198.51"), dests("com.android.chrome", 90, 443, "203.0")...)
	f := one(t, Fanout(hour0, ds, 2, nil, th), TypeFanout, "com.proxy.sdk")
	if f.Evidence["addresses"] != 101 || f.Evidence["threshold"] != 100 || f.Evidence["connections"] != int64(202) ||
		len(f.Evidence["sample"].([]any)) != maxSample || f.FromMS != hour0 || f.ToMS != hour0+hourMS {
		t.Fatalf("%+v", f)
	}
	none(t, Fanout(hour0, ds[:100], 2, nil, th), "100 addresses screen off")
	none(t, Fanout(hour0, ds, 30, nil, th), "101 addresses screen on")
	none(t, Fanout(hour0, ds, -1, nil, th), "screen unknown: the higher threshold")
	one(t, Fanout(hour0, dests("com.proxy.sdk", 301, 443, "198.51"), 60, nil, th), TypeFanout, "com.proxy.sdk")
	// The same address on several ports counts once; keys are parsed.
	var rows []store.ConnectRow
	for p := 1; p <= 400; p++ {
		rows = append(rows, store.ConnectRow{Package: "com.scan", Key: fmt.Sprintf("192.0.2.1:%d", p), Count: 1})
	}
	rows = append(rows, store.ConnectRow{Package: "x", Key: "[2001:db8::1]:443", Count: 1}, store.ConnectRow{Package: "x", Key: "pas-une-ip", Count: 1})
	parsed := Dests(rows)
	if len(parsed) != 401 || parsed[400].Port != 443 || MaxDistinct(parsed) != 1 {
		t.Fatalf("dests %d %d", len(parsed), MaxDistinct(parsed))
	}
	none(t, Fanout(hour0, parsed, 0, nil, th), "one address, many ports")
	none(t, Fanout(hour0, nil, 0, nil, th), "no data")
}

func TestMailPorts(t *testing.T) {
	th := Defaults()
	day := hour0 - hour0%dayMS
	ds := append(dests("com.cleaner.boost", 30, 587, "198.51"), dests("com.samsung.android.email.provider", 2, 465, "203.0")...)
	ds = append(ds, dests("com.cleaner.boost", 5, 443, "192.0")...)
	f := one(t, MailPortsRule(day, ds, Labels{"com.cleaner.boost": "Cleaner"}, th), TypeMailPorts, "com.cleaner.boost")
	if f.Sev != 3 || f.Evidence["connections"] != int64(60) || f.Evidence["addresses"] != 30 || !strings.HasPrefix(f.Summary, "Cleaner") {
		t.Fatalf("%+v", f)
	}
	g := one(t, MailPortsRule(day, dests("com.game", 1, 25, "198.51")[:1], nil, th), TypeMailPorts, "com.game")
	if g.Sev != 2 {
		t.Fatalf("one connection: %+v", g)
	}
	th.MailMin = 3
	none(t, MailPortsRule(day, dests("com.game", 1, 25, "198.51"), nil, th), "2 connections under a minimum of 3")
	none(t, MailPortsRule(day, dests("com.samsung.android.email.provider", 50, 587, "198.51"), nil, Defaults()), "mail client")
	none(t, MailPortsRule(day, dests("com.game", 50, 993, "198.51"), nil, Defaults()), "IMAP is not sending")
}

func TestDNSBypass(t *testing.T) {
	th := Defaults()
	res := DefaultResolvers()
	day := hour0 - hour0%dayMS
	ds := []Dest{{Package: "com.secure.browser", Addr: netip.MustParseAddr("1.1.1.1"), Port: 443, Count: 40},
		{Package: "com.secure.browser", Addr: netip.MustParseAddr("8.8.8.8"), Port: 853, Count: 2},
		{Package: "com.game", Addr: netip.MustParseAddr("8.8.8.8"), Port: 53, Count: 10}, // connectivity check idiom: port not followed
		{Package: "com.android.chrome", Addr: netip.MustParseAddr("142.250.75.238"), Port: 443, Count: 90}}
	f := one(t, DNSBypass(day, ds, res, nil, th), TypeDNSBypass, "com.secure.browser")
	if f.Evidence["connections"] != int64(42) || len(f.Evidence["providers"].([]any)) != 2 || f.Evidence["resolvers"].([]any)[0] != "1.1.1.1:443" {
		t.Fatalf("%+v", f)
	}
	th.DNSBypassExempt = map[string]bool{"com.secure.browser": true}
	none(t, DNSBypass(day, ds, res, nil, th), "exempt")
	th = Defaults()
	th.DNSBypassMin = 43
	none(t, DNSBypass(day, ds, res, nil, th), "42 connections under 43")
}

func TestThreatDomain(t *testing.T) {
	day := hour0 - hour0%dayMS
	in := ThreatInput{DayMS: day,
		Blocks: []store.ThreatBlock{{Domain: "gate.cdn-update-check.example", Blocked: 12, Reason: "Liste : HaGeZi TIF"},
			{Domain: "login-banque.example", Blocked: 1, Reason: "Navigation sécurisée (site dangereux)"}},
		Lookups: []store.DNSLookup{{Package: "com.update.system", Domain: "gate.cdn-update-check.example", Count: 12},
			{Package: "com.android.chrome", Domain: "login-banque.example", Count: 1},
			{Package: "com.whatsapp", Domain: "g.whatsapp.net", Count: 500}},
		Browsers: map[string]bool{"com.android.chrome": true}}
	fs := ThreatDomain(in)
	if len(fs) != 2 || fs[0].Package != "com.android.chrome" || fs[0].Sev != 2 || fs[1].Package != "com.update.system" || fs[1].Sev != 3 ||
		fs[1].Subject != "com.update.system|gate.cdn-update-check.example" || fs[1].Evidence["blocked"] != int64(12) {
		t.Fatalf("%+v", fs)
	}
	none(t, ThreatDomain(ThreatInput{DayMS: day, Lookups: in.Lookups}), "no threat block")
	none(t, ThreatDomain(ThreatInput{DayMS: day, Blocks: in.Blocks}), "no lookup")
}

func TestSMSAbuse(t *testing.T) {
	th := Defaults()
	day := hour0 - hour0%dayMS
	uses := []store.OpUse{
		{Package: "com.flashlight.pro", Op: "send_sms", Count: 1980, Background: 1980}, {Package: "com.flashlight.pro", Op: "read_contacts", Count: 3},
		{Package: "com.samsung.android.messaging", Op: "send_sms", Count: 12},
		{Package: "com.google.android.gms", Op: "send_sms", Count: 1}, // system application
	}
	sms := map[string]bool{"com.samsung.android.messaging": true}
	system := map[string]bool{"com.google.android.gms": true, "com.samsung.android.messaging": true}
	f := one(t, SMSAbuse(OpsInput{DayMS: day, Uses: uses, SMSApps: sms, System: system}, th), TypeSMSAbuse, "com.flashlight.pro")
	if f.Evidence["reason"] != "not_default_sms_app" || f.Evidence["sent"] != int64(1980) || f.Evidence["read_contacts"] != int64(3) || f.Sev != 3 {
		t.Fatalf("%+v", f)
	}
	// SMS app unknown: only the volume counts.
	f = one(t, SMSAbuse(OpsInput{DayMS: day, Uses: uses, System: system}, th), TypeSMSAbuse, "com.flashlight.pro")
	if f.Evidence["reason"] != "volume" {
		t.Fatalf("%+v", f)
	}
	under := []store.OpUse{{Package: "com.samsung.android.messaging", Op: "send_sms", Count: th.SMSDailyMax}}
	none(t, SMSAbuse(OpsInput{DayMS: day, Uses: under, SMSApps: sms, System: system}, th), "default app at the daily maximum")
	under[0].Count++
	one(t, SMSAbuse(OpsInput{DayMS: day, Uses: under, SMSApps: sms, System: system}, th), TypeSMSAbuse, "com.samsung.android.messaging")
	th.SMSOtherMin = 2
	none(t, SMSAbuse(OpsInput{DayMS: day, Uses: []store.OpUse{{Package: "com.x", Op: "send_sms", Count: 1}}, SMSApps: sms}, th), "1 SMS under 2")
	none(t, SMSAbuse(OpsInput{DayMS: day}, th), "no app.ops")
}

func TestSensorBackground(t *testing.T) {
	th := Defaults()
	day := hour0 - hour0%dayMS
	uses := []store.OpUse{
		{Package: "com.qrscan", Op: "record_audio", Count: 40, Background: 36}, {Package: "com.qrscan", Op: "camera", Count: 3, Background: 3},
		{Package: "com.whatsapp", Op: "record_audio", Count: 12, Background: 9},
		{Package: "com.google.android.googlequicksearchbox", Op: "record_audio", Count: 200, Background: 200},
		{Package: "com.samsung.android.bixby.agent", Op: "record_audio", Count: 50, Background: 50},
	}
	in := OpsInput{DayMS: day, Uses: uses, System: map[string]bool{"com.samsung.android.bixby.agent": true},
		SensorExempt: map[string]bool{"com.google.android.googlequicksearchbox": true}}
	fs := SensorBackground(in, th)
	if len(fs) != 2 || fs[0].Subject != "com.qrscan|record_audio" || fs[1].Subject != "com.qrscan|camera" {
		t.Fatalf("%+v", fs)
	}
	in.Uses = uses[2:3] // 9 background uses, threshold 10
	none(t, SensorBackground(in, th), "under the threshold")
	in.Uses = []store.OpUse{{Package: "com.whatsapp", Op: "record_audio", Count: 12, Background: 10}}
	one(t, SensorBackground(in, th), TypeSensorBackground, "com.whatsapp")
	none(t, SensorBackground(OpsInput{DayMS: day}, th), "no app.ops")
}

func TestNewAppRisky(t *testing.T) {
	inst := hour0 + 600000
	fs := true
	in := NewAppInput{
		Installs: []Install{{Package: "com.update.system", Installer: "com.google.android.packageinstaller", TS: inst},
			{Package: "fr.vinted", Installer: "com.android.vending", TS: inst}, {Package: "io.github.erwsim.vigie", TS: inst}},
		Risks: []Risk{{Package: "com.update.system", Label: "Mise à jour système", Level: "high", Score: 92, TS: inst + 2000,
			Reasons: []string{"sideloaded", "accessibility_service", "overlay", "combo_banking_trojan"}},
			{Package: "fr.vinted", Level: "low", Score: 10, TS: inst + 1000, FromStore: &fs}},
		Caps: []Capability{{Package: "com.update.system", Kind: "accessibility", TS: inst + 5*60000},
			{Package: "com.update.system", Kind: "accessibility", TS: inst + 6*60000},      // same capability again
			{Package: "com.update.system", Kind: "overlay", TS: inst + 25*3600000},         // after 24 h
			{Package: "fr.vinted", Kind: "permission:CAMERA", TS: inst + 60000},            // not sensitive
			{Package: "com.android.chrome", Kind: "permission:SEND_SMS", TS: inst + 60000}, // not a new app
			{Package: "io.github.erwsim.vigie", Kind: "device_admin", TS: inst + 60000}},   // Vigie itself
	}
	out := NewAppRisky(in)
	if len(out) != 2 || out[0].Subject != "com.update.system|high_risk" || out[0].Sev != 3 || out[0].Label != "Mise à jour système" ||
		out[1].Subject != "com.update.system|accessibility" || out[1].Evidence["minutes_after_install"] != int64(5) || out[0].FromMS != inst {
		t.Fatalf("%+v", out)
	}
	// A high-risk app.risk more than 24 h after the installation is not "just installed".
	in.Risks[0].TS = inst + 25*3600000
	in.Caps = nil
	none(t, NewAppRisky(in), "late risk")
	in.Risks[0].TS, in.Risks[0].Level = inst, "medium"
	none(t, NewAppRisky(in), "medium risk")
	none(t, NewAppRisky(NewAppInput{Risks: in.Risks}), "no installation")
}

func TestBytesFR(t *testing.T) {
	for n, want := range map[int64]string{512: "512 o", 1536: "1,5 Kio", 3 << 30: "3 Gio"} {
		if got := bytesFR(n); got != want {
			t.Errorf("%d: %q", n, got)
		}
	}
}
