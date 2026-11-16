package sim

import (
	"regexp"
	"strings"
	"time"
)

// importance of a notification channel (NotificationManager.IMPORTANCE_*).
func importance(category string) int {
	switch category {
	case "msg", "email":
		return 4
	case "recommendation", "social":
		return 3
	}
	return 3
}

// contentExcluded lists the apps whose notification content is never collected (setting of the
// companion APK, contract §10): here the banking app.
var contentExcluded = map[string]bool{"fr.creditagricole.androidapp": true}

var notificationTexts = map[string][][2]string{
	"com.whatsapp":                       {{"Maman", "Tu passes dimanche ?"}, {"Thomas", "Ok pour ce soir, 20 h devant le métro"}, {"Escalade du jeudi", "Léa : qui a la corde ?"}},
	"org.thoughtcrime.securesms":         {{"Alice", "Je t'envoie le document ce soir"}, {"Alice", "Bien reçu, merci !"}},
	"org.telegram.messenger":             {{"Canal Infos Vélo", "Nouvelle piste cyclable rue de Rivoli"}},
	"com.samsung.android.messaging":      {{"38XXX", "Votre code de vérification est 483920. Ne le communiquez à personne."}, {"Pharmacie", "Votre commande est prête"}, {"Banque", "Code de sécurité : 7731 pour valider votre paiement"}},
	"com.samsung.android.email.provider": {{"Fastmail", "Facture de novembre disponible"}, {"Mairie du 11e", "Votre rendez-vous du 21/11"}},
	"fr.lemonde.editorial":               {{"Le Monde", "Alerte : le Parlement adopte le budget"}, {"Le Monde", "Les principales informations de la journée"}},
	"com.instagram.android":              {{"Instagram", "thomas_r a aimé votre publication"}},
	"com.strava":                         {{"Strava", "Thomas vous a donné un kudo"}, {"Strava", "Nouveau record personnel sur le segment Bois de Vincennes"}},
}

var codeRe = regexp.MustCompile(`\b[0-9]{4,8}\b`)

// maskCodes hides the numeric codes of 4 to 8 digits, as the companion APK does by default.
func maskCodes(s string) (string, bool) {
	masked := codeRe.ReplaceAllStringFunc(s, func(m string) string { return strings.Repeat("•", len(m)) })
	return masked, masked != s
}

// notificationContent adds title and text (drawn from nrng, a separate stream) unless the app is excluded.
func (g *Generator) notificationContent(pkg string, d map[string]any) {
	texts := notificationTexts[pkg]
	if contentExcluded[pkg] || len(texts) == 0 {
		return
	}
	tt := texts[g.nrng.Intn(len(texts))]
	title, r1 := maskCodes(tt[0])
	text, r2 := maskCodes(tt[1])
	d["title"], d["text"] = title, text
	if r1 || r2 {
		d["redacted"] = true
	}
}

// collectorStates is the "collectors" object of agent.heartbeat.
func (g *Generator) collectorStates() map[string]any {
	out := make(map[string]any, len(collectors))
	for k, v := range collectors {
		out[k] = v
	}
	if g.content {
		out["notification_content"] = "running"
	}
	return out
}

// feedDNS reports each occurrence of a lookup (a grouped net.dns spreads them up to last_event_ts).
func (g *Generator) feedDNS(t time.Time, host string, d map[string]any) {
	n := 1
	if c, ok := d["count"].(int); ok && c > 1 {
		n = c
	}
	last := t
	if s, ok := d["last_event_ts"].(string); ok {
		if lt, err := time.Parse(time.RFC3339Nano, s); err == nil && lt.After(t) {
			last = lt
		}
	}
	for i := range n {
		at := t
		if n > 1 {
			at = t.Add(last.Sub(t) * time.Duration(i) / time.Duration(n-1))
		}
		g.onDNS(at, host)
	}
}
