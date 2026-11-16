package tracking

import "strings"

// Essential is a domain that cannot be blocked from the console without an explicit confirmation
// ("force": true), with what blocking it would break (contract §9).
type Essential struct {
	Domain string `json:"domain"`
	Breaks string `json:"breaks"`
}

// builtinEssentials is the exception list of Vigie: push notifications (FCM), connectivity check,
// network time and updates.
var builtinEssentials = []Essential{
	{"mtalk.google.com", "notifications push (Firebase Cloud Messaging) : messageries, banque, double authentification"},
	{"fcm.googleapis.com", "notifications push (Firebase Cloud Messaging)"},
	{"android.googleapis.com", "enregistrement des notifications push (FCM) et services Google Play"},
	{"firebaseinstallations.googleapis.com", "enregistrement des notifications push (FCM) des applications"},
	{"connectivitycheck.gstatic.com", "test de connectivité Android : Wi-Fi marqué « sans Internet », bascule sur les données mobiles"},
	{"connectivitycheck.android.com", "test de connectivité Android"},
	{"clients3.google.com", "test de connectivité Android (ancien point de test)"},
	{"time.android.com", "mise à l'heure réseau (NTP) : certificats TLS et double authentification"},
	{"fota-cloud-dn.ospserver.net", "mises à jour système Samsung (téléchargement)"},
	{"fota-apis.samsungdm.com", "mises à jour système Samsung (vérification)"},
	{"android.clients.google.com", "mises à jour des applications (Play Store) et des services Google Play"},
	{"play.googleapis.com", "Play Store et mises à jour des applications"},
	{"play-fe.googleapis.com", "Play Store"},
	{"update.googleapis.com", "mises à jour des composants système (Google Play system update)"},
	{"dl.google.com", "téléchargement des mises à jour Google"},
	{"gvt1.com", "téléchargement des mises à jour des applications et du système (Google)"},
}

// Essentials holds the exception list, completed with the hosts of the Vigie deployment itself.
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
