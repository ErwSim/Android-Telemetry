package detect

import (
	"net/netip"
	"testing"

	"github.com/erwsim/android-telemetry/server/collector/internal/store"
)

// Review of v1.2. These tests pin what the detections do NOT see, so that the README stays true and a
// future detection that closes a gap has to say so here.

// The attack the owner lived through: a discreet application sends about 2 000 SMS a day. SMS do not use
// the IP network, so without app.ops (experimental on the phone, possibly never available) nothing counts
// them. What remains is the day of the installation: detect.new_app_risky, and only if the permission is
// granted within 24 hours of it.
func TestOwnerScenarioWithoutAppOps(t *testing.T) {
	const app = "com.coupons.promo.deals"
	install := Install{Package: app, Installer: "com.android.vending", TS: hour0}
	// As the real agent rates it at installation: SEND_SMS is only counted once granted (android/README).
	risk := Risk{Package: app, Label: "Promo Coupons", Level: "medium", Score: 32, Reasons: []string{"sideloaded", "no_launcher_icon", "boot_receiver"}, TS: hour0 + 5_000}
	late := Capability{Package: app, Kind: "permission:SEND_SMS", TS: hour0 + 30*hourMS}
	none(t, NewAppRisky(NewAppInput{Installs: []Install{install}, Risks: []Risk{risk}, Caps: []Capability{late}}),
		"permission granted 30 h after the installation")
	// The same day seen by every other rule: a small poll of its panel, a few kilobytes.
	day := dayOf(late.TS)
	dests := []Dest{{Package: app, Addr: netip.MustParseAddr("203.0.113.77"), Port: 443, Count: 48}}
	th := Defaults()
	none(t, SMSAbuse(OpsInput{DayMS: day, SMSApps: map[string]bool{"com.google.android.apps.messaging": true}}, th), "no app.ops, no count of SMS")
	none(t, Fanout(late.TS, dests, 0, Labels{}, th), "one address")
	none(t, MailPortsRule(day, dests, Labels{}, th), "no mail port")
	none(t, DNSBypass(day, dests, DefaultResolvers(), Labels{}, th), "not a resolver")
	none(t, UploadSpike(UploadInput{HourMS: late.TS, Tx: map[string]int64{app: 25_000}}, th), "25 kB an hour")

	// Granted within the day: reported once, as a capability obtained by a new application.
	early := Capability{Package: app, Kind: "permission:SEND_SMS", TS: hour0 + 3*60_000}
	f := one(t, NewAppRisky(NewAppInput{Installs: []Install{install}, Risks: []Risk{risk}, Caps: []Capability{early}}), TypeNewAppRisky, app)
	if f.Sev != 2 {
		t.Fatalf("severity %d", f.Sev)
	}
	// With app.ops the first hour is enough.
	uses := []store.OpUse{{Package: app, Op: "send_sms", Count: 85, Background: 85}}
	one(t, SMSAbuse(OpsInput{DayMS: day, Uses: uses, SMSApps: map[string]bool{"com.google.android.apps.messaging": true}}, th), TypeSMSAbuse, app)
}

// A healthy but busy phone rings: each case below is a real habit, not an attack. Kept as a test so that
// the list of foreseeable false positives of the README is exact.
func TestForeseeableFalsePositives(t *testing.T) {
	th := Defaults()
	day := dayOf(hour0)
	// A browser, a messenger or Play services using a public resolver over HTTPS.
	for pkg, ip := range map[string]string{"org.mozilla.firefox": "104.16.248.249", "org.telegram.messenger": "8.8.8.8", "com.google.android.gms": "8.8.4.4"} {
		one(t, DNSBypass(day, []Dest{{Package: pkg, Addr: netip.MustParseAddr(ip), Port: 443, Count: 1}}, DefaultResolvers(), Labels{}, th), TypeDNSBypass, pkg)
	}
	// A mail client that is not in mail_clients.txt.
	one(t, MailPortsRule(day, []Dest{{Package: "ru.yandex.mail", Addr: netip.MustParseAddr("77.88.21.158"), Port: 465, Count: 3}}, Labels{}, th), TypeMailPorts, "ru.yandex.mail")
	// The first backup of a holiday's photos, or a one-hour HD video call.
	in := UploadInput{HourMS: hour0, Tx: map[string]int64{"com.google.android.apps.photos": 3 << 30}, History: map[string][]int64{"com.google.android.apps.photos": make([]int64, 200)}}
	one(t, UploadSpike(in, th), TypeUploadSpike, "com.google.android.apps.photos")
	// A podcast or RSS application refreshing 130 feeds (IPv4 and IPv6) at night.
	var dests []Dest
	for i := 0; i < 260; i++ {
		dests = append(dests, Dest{Package: "de.danoeh.antennapod", Addr: netip.AddrFrom4([4]byte{198, 51, byte(100 + i/250), byte(i%250 + 1)}), Port: 443, Count: 1})
	}
	one(t, Fanout(hour0, dests, 0, Labels{}, th), TypeFanout, "de.danoeh.antennapod")
}
