package tracking

import "strings"

// Essential is a domain that cannot be blocked from the console without an explicit confirmation
// ("force": true), with what blocking it would break (contract §9).
type Essential struct {
	Domain string `json:"domain"`
	Breaks string `json:"breaks"`
}

// builtinEssentials is the exception list of Watchpost: push notifications (FCM), connectivity check,
// network time and updates.
var builtinEssentials = []Essential{
	{"mtalk.google.com", "push notifications (Firebase Cloud Messaging): messaging, banking, two-factor authentication"},
	{"fcm.googleapis.com", "push notifications (Firebase Cloud Messaging)"},
	{"android.googleapis.com", "push notification (FCM) registration and Google Play services"},
	{"firebaseinstallations.googleapis.com", "push notification (FCM) registration of applications"},
	{"connectivitycheck.gstatic.com", "Android connectivity check: Wi-Fi flagged \"no Internet\", falls back to mobile data"},
	{"connectivitycheck.android.com", "Android connectivity check"},
	{"clients3.google.com", "Android connectivity check (legacy endpoint)"},
	{"time.android.com", "network time (NTP): TLS certificates and two-factor authentication"},
	{"fota-cloud-dn.ospserver.net", "Samsung system updates (download)"},
	{"fota-apis.samsungdm.com", "Samsung system updates (check)"},
	{"android.clients.google.com", "application updates (Play Store) and Google Play services"},
	{"play.googleapis.com", "Play Store and application updates"},
	{"play-fe.googleapis.com", "Play Store"},
	{"update.googleapis.com", "system component updates (Google Play system update)"},
	{"dl.google.com", "Google update downloads"},
	{"gvt1.com", "application and system update downloads (Google)"},
}

// Essentials holds the exception list, completed with the hosts of the Watchpost deployment itself.
type Essentials struct{ list []Essential }

// NewEssentials returns the built-in list plus the given hosts (ingestion host, private DNS host).
func NewEssentials(own map[string]string) *Essentials {
	e := &Essentials{list: append([]Essential(nil), builtinEssentials...)}
	for host, what := range own {
		if h := Normalize(host); ValidDomain(h) {
			e.list = append(e.list, Essential{Domain: h, Breaks: what})
		}
	}
	return e
}

// BrokenBy returns the essential domains that blocking domain would affect: the domain itself and its
// subdomains, since "||domain^" also blocks every subdomain.
func (e *Essentials) BrokenBy(domain string) []Essential {
	d := Normalize(domain)
	var out []Essential
	for _, x := range e.list {
		if x.Domain == d || strings.HasSuffix(x.Domain, "."+d) {
			out = append(out, x)
		}
	}
	return out
}
