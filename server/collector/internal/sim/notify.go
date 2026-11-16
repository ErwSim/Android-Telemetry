package sim

import (
	"regexp"
	"strings"
	"time"
)

// importance of a notification channel, as the companion APK reports it (contract §10): the name of
// NotificationManager.IMPORTANCE_* among none/min/low/default/high/max, never the number.
func importance(category string) string {
	switch category {
	case "msg", "email":
		return "high"
	}
	return "default"
}

// contentExcluded lists the apps whose notification content is never collected (setting of the
// companion APK, contract §10): here the banking app.
var contentExcluded = map[string]bool{"com.mybank.app": true}

var notificationTexts = map[string][][2]string{
	"com.whatsapp":                       {{"Mom", "Are you coming on Sunday?"}, {"Thomas", "Ok for tonight, 8 pm in front of the station"}, {"Thursday climbing", "Lea: who has the rope?"}},
	"org.thoughtcrime.securesms":         {{"Alice", "I'll send you the document tonight"}, {"Alice", "Got it, thanks!"}},
	"org.telegram.messenger":             {{"Cycling News Channel", "New bike lane on Main Street"}},
	"com.samsung.android.messaging":      {{"38XXX", "Your verification code is 483920. Do not share it with anyone."}, {"Pharmacy", "Your order is ready"}, {"Bank", "Security code: 7731 to confirm your payment"}},
	"com.samsung.android.email.provider": {{"Fastmail", "November invoice available"}, {"City Hall", "Your appointment on Nov 21"}},
	"com.dailynews.reader":               {{"Daily News", "Alert: Parliament passes the budget"}, {"Daily News", "Today's top stories"}},
	"com.instagram.android":              {{"Instagram", "thomas_r liked your post"}},
	"com.strava":                         {{"Strava", "Thomas gave you kudos"}, {"Strava", "New personal record on the Riverside Park segment"}},
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
