package tracking

import (
	"slices"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	c := Default()
	cases := map[string]string{
		"google.com":                           "google",
		"www.google.com":                       "google",
		"WWW.Google.COM.":                      "google",
		"notgoogle.com":                        Other,
		"google.com.evil.example":              Other,
		"app-measurement.com":                  "google",
		"securepubads.g.doubleclick.net":       "google",
		"rr3---sn-25ge7nsk.googlevideo.com":    "google",
		"dc.samsungdm.com":                     "samsung",
		"fota-cloud-dn.ospserver.net":          "samsung",
		"graph.facebook.com":                   "meta",
		"scontent-cdg4-1.cdninstagram.com":     "meta",
		"mmg.whatsapp.net":                     "meta",
		"incoming.telemetry.mozilla.org":       Other,
		"login.microsoftonline.com":            "microsoft",
		"s3.eu-west-3.amazonaws.com":           "amazon",
		"v16m.tiktokcdn.com":                   "bytedance",
		"sb.scorecardresearch.com":             "ads",
		"api.segment.io":                       "ads",
		"unityads.unity3d.com":                 "ads",
		"config.unityads.unity3d.com":          "ads",
		"unity3d.com":                          Other,
		"com":                                  Other,
		"":                                     Other,
		"tags.tiqcdn.com":                      "ads",
		"lpa.ds.gsma.com":                      Other,
		"firebaseinstallations.googleapis.com": "google",
	}
	for d, want := range cases {
		if got := c.Classify(d); got != want {
			t.Errorf("Classify(%q) = %q, want %q", d, got, want)
		}
	}
	var keys []string
	for _, p := range c.Publishers() {
		keys = append(keys, p.Key)
	}
	if !slices.Equal(keys, []string{"google", "samsung", "meta", "microsoft", "amazon", "bytedance", "ads", "other"}) {
		t.Fatalf("publishers %v", keys)
	}
}

func TestParsePublishersErrors(t *testing.T) {
	bad := []string{
		"google.com\n[other] Autres\n",                           // suffix before publisher
		"[a] A\nexample.com\n[b] B\nexample.com\n[other] Autres", // duplicate suffix
		"[a] A\n[a] A2\n[other] Autres",                          // duplicate publisher
		"[a] A\nexample.com\n",                                   // no "other"
		"[a] A\nexa mple.com\n[other] Autres",                    // invalid suffix
		"[other] Autres\nexample.com",                            // suffix on other
	}
	for _, b := range bad {
		if _, err := ParsePublishers(b); err == nil {
			t.Errorf("accepted %q", b)
		}
	}
}

func TestValidDomain(t *testing.T) {
	ok := []string{"example.com", "a.b.c.example.co.uk", "xn--d1abbgf6aiiy.xn--p1ai", "_dmarc.example.com", "a-b.example.com", "1.example.com"}
	for _, d := range ok {
		if !ValidDomain(d) {
			t.Errorf("%q refused", d)
		}
	}
	bad := []string{"", "com", "Example.com", "example.com.", ".example.com", "-a.example.com", "a-.example.com",
		"exa mple.com", "example.com^", "||example.com", "example.com$important", "example.com\n||evil.com^",
		"@@example.com", "example.com/path", "*.example.com", "192.168.1.1", "a..b.com", strings.Repeat("a", 64) + ".com",
		strings.Repeat("abcdefghi.", 26) + "com", "exämple.com", "example.com!", "example.com#x", "example.com,evil.com"}
	for _, d := range bad {
		if ValidDomain(d) {
			t.Errorf("%q accepted", d)
		}
	}
}

func TestEssentials(t *testing.T) {
	e := NewEssentials(map[string]string{"ingest.vigie.example": "envoi des événements Vigie", "not a host": "x"})
	if got := e.BrokenBy("google.com"); len(got) < 2 {
		t.Fatalf("google.com breaks %v", got)
	}
	if got := e.BrokenBy("mtalk.google.com"); len(got) != 1 || got[0].Domain != "mtalk.google.com" {
		t.Fatalf("mtalk %v", got)
	}
	if got := e.BrokenBy("sub.mtalk.google.com"); len(got) != 0 {
		t.Fatalf("subdomain of an essential domain does not break it: %v", got)
	}
	if got := e.BrokenBy("vigie.example"); len(got) != 1 {
		t.Fatalf("own host %v", got)
	}
	if got := e.BrokenBy("doubleclick.net"); len(got) != 0 {
		t.Fatalf("doubleclick %v", got)
	}
}

func TestApplyOverride(t *testing.T) {
	user := []string{"||ads.example.org^", "# règle à la main", "@@||bank.example^"}
	r1, changed, err := ApplyOverride(user, "tracker.example.com", ActionBlock)
	if err != nil || !changed {
		t.Fatal(err, changed)
	}
	want := append(append([]string{}, user...), BlockBegin, "||tracker.example.com^$important", BlockEnd)
	if !slices.Equal(r1, want) {
		t.Fatalf("got %q", r1)
	}
	// Idempotent.
	r2, changed, err := ApplyOverride(r1, "tracker.example.com", ActionBlock)
	if err != nil || changed || !slices.Equal(r2, r1) {
		t.Fatalf("second application changed the rules: %q", r2)
	}
	r3, _, _ := ApplyOverride(r1, "app.example.net", ActionAllow)
	ov, err := ParseOverrides(r3)
	if err != nil || ov["tracker.example.com"] != ActionBlock || ov["app.example.net"] != ActionAllow || len(ov) != 2 {
		t.Fatalf("overrides %v %v", ov, err)
	}
	if !slices.Equal(r3[:3], user) {
		t.Fatalf("user rules touched: %q", r3)
	}
	// Rules added by hand after the block stay where they are.
	r3 = append(r3, "||later.example^")
	r4, _, _ := ApplyOverride(r3, "tracker.example.com", ActionDefault)
	r5, _, _ := ApplyOverride(r4, "app.example.net", ActionDefault)
	if !slices.Equal(r5, append(append([]string{}, user...), "||later.example^")) {
		t.Fatalf("block not removed cleanly: %q", r5)
	}
	if _, _, err := ApplyOverride(user, "evil.com^\n||google.com", ActionBlock); err == nil {
		t.Fatal("rule injection accepted")
	}
	for _, corrupt := range [][]string{{BlockBegin}, {BlockEnd}, {BlockBegin, BlockBegin, BlockEnd}, {BlockEnd, BlockBegin}} {
		if _, _, err := ApplyOverride(corrupt, "a.example", ActionBlock); err != ErrCorruptBlock {
			t.Fatalf("corrupt block %q: %v", corrupt, err)
		}
	}
}

// Contract §9: "les règles saisies à la main dans AdGuard ne sont pas touchées" — also when the owner (or
// AdGuard Home) put some between the markers of the managed block.
func TestApplyOverrideKeepsForeignLinesOfTheBlock(t *testing.T) {
	rules := []string{
		"||before.example^",
		BlockBegin,
		"||tracker.example.com^$important",
		"||hand-made.example^",           // not written by Vigie (no $important)
		"! note du propriétaire",         // a comment
		"@@||app.example.net^$important", // ours
		"",
		"||other.example^$important,client=1.2.3.4", // looks like ours, is not
		BlockEnd,
		"||after.example^",
	}
	out, changed, err := ApplyOverride(rules, "new.example.org", ActionBlock)
	if err != nil || !changed {
		t.Fatal(err, changed)
	}
	want := []string{
		"||before.example^",
		BlockBegin,
		"@@||app.example.net^$important",
		"||new.example.org^$important",
		"||tracker.example.com^$important",
		BlockEnd,
		"||hand-made.example^",
		"! note du propriétaire",
		"||other.example^$important,client=1.2.3.4",
		"||after.example^",
	}
	if !slices.Equal(out, want) {
		t.Fatalf("got %q", out)
	}
	// Removing every override removes the block and nothing else.
	for _, d := range []string{"new.example.org", "tracker.example.com", "app.example.net"} {
		if out, _, err = ApplyOverride(out, d, ActionDefault); err != nil {
			t.Fatal(err)
		}
	}
	want = []string{"||before.example^", "||hand-made.example^", "! note du propriétaire", "||other.example^$important,client=1.2.3.4", "||after.example^"}
	if !slices.Equal(out, want) {
		t.Fatalf("after removal: %q", out)
	}
}

const levelsJSON = `{
  "version": 1,
  "lists": {
    "base": {"name": "Base", "url": "https://lists.example/base.txt"},
    "samsung": {"name": "Samsung", "url": "https://lists.example/samsung.txt"},
    "google": {"name": "Google", "url": "/opt/adguardhome/lists/google.txt"},
    "fcm": {"name": "Exceptions", "url": "https://lists.example/allow.txt", "allowlist": true}
  },
  "levels": [
    {"key": "permissif", "name": "Permissif", "description": "Publicité", "lists": ["base"]},
    {"key": "equilibre", "name": "Équilibré", "description": "", "lists": ["base", "samsung", "fcm"]},
    {"key": "strict", "name": "Strict", "description": "Tout", "lists": ["base", "samsung", "google", "fcm"]}
  ]
}`

func TestLevels(t *testing.T) {
	l, err := ParseLevels([]byte(levelsJSON))
	if err != nil {
		t.Fatal(err)
	}
	if infos := l.Infos(); len(infos) != 3 || infos[1].Key != "equilibre" || infos[1].Name != "Équilibré" {
		t.Fatalf("infos %+v", infos)
	}
	filters := []FilterState{
		{URL: "https://lists.example/base.txt", Name: "Base", Enabled: true},
		{URL: "https://lists.example/samsung.txt", Name: "Samsung", Enabled: false},
		{URL: "https://other.example/x.txt", Name: "Liste à la main", Enabled: true},
	}
	if cur := l.Current(filters); cur != "permissif" {
		t.Fatalf("current %q", cur)
	}
	plan, err := l.Plan("strict", filters)
	if err != nil {
		t.Fatal(err)
	}
	if len(plan) != 3 || !plan[0].Add || !plan[0].Allowlist || !plan[1].Add || plan[1].URL != "/opt/adguardhome/lists/google.txt" ||
		plan[2].Add || !plan[2].Enabled || plan[2].Name != "Samsung" {
		t.Fatalf("plan %+v", plan)
	}
	after := append(filters, FilterState{URL: "https://lists.example/allow.txt", Enabled: true, Allowlist: true},
		FilterState{URL: "/opt/adguardhome/lists/google.txt", Enabled: true})
	after[1].Enabled = true
	if cur := l.Current(after); cur != "strict" {
		t.Fatalf("current after %q", cur)
	}
	if plan, _ := l.Plan("strict", after); len(plan) != 0 {
		t.Fatalf("plan not idempotent %+v", plan)
	}
	if _, err := l.Plan("max", after); err == nil {
		t.Fatal("unknown level planned")
	}
	bad := []string{
		strings.Replace(levelsJSON, `"version": 1`, `"version": 2`, 1),
		strings.Replace(levelsJSON, `"strict"`, `"extreme"`, 1),
		strings.Replace(levelsJSON, `"lists": ["base"]`, `"lists": ["nope"]`, 1),
		strings.Replace(levelsJSON, `https://lists.example/samsung.txt`, `https://lists.example/base.txt`, 1),
		strings.Replace(levelsJSON, `/opt/adguardhome/lists/google.txt`, `lists/google.txt`, 1),
		strings.Replace(levelsJSON, `"version": 1,`, `"version": 1, "extra": true,`, 1),
		strings.Replace(levelsJSON, `"name": "Base"`, `"name": ""`, 1),
		strings.Replace(levelsJSON, `{"key": "permissif", "name": "Permissif", "description": "Publicité", "lists": ["base"]},`, ``, 1),
	}
	for i, b := range bad {
		if _, err := ParseLevels([]byte(b)); err == nil {
			t.Errorf("bad levels file %d accepted", i)
		}
	}
}

func TestView(t *testing.T) {
	in := &Input{
		AdGuard: true,
		AdGuardCounts: map[string]DomainCount{
			"app-measurement.com": {Queries: 100, Blocked: 100, Reason: "Liste : AdGuard DNS filter"},
			"www.google.com":      {Queries: 50, Blocked: 0},
			"graph.facebook.com":  {Queries: 10, Blocked: 5},
		},
		DNS: []AppDomain{
			{Package: "com.example.news", Domain: "app-measurement.com", Count: 30},
			{Package: "com.example.news", Domain: "www.lemonde.fr", Count: 10},
			{Package: "com.instagram.android", Domain: "graph.facebook.com", Count: 8},
			{Package: "", Domain: "www.google.com", Count: 4},
		},
		Usage:      map[string]Bytes{"com.example.news": {Rx: 4000, Tx: 400}, "com.spotify.music": {Rx: 9000, Tx: 100}},
		Overrides:  map[string]string{"graph.facebook.com": ActionBlock},
		Labels:     map[string]string{"com.instagram.android": "Instagram"},
		Classifier: Default(),
	}
	ds := Domains(in)
	if len(ds) != 4 || ds[0].Domain != "app-measurement.com" || ds[0].Status != StatusBlocked || ds[0].Reason == "" ||
		ds[1].Status != StatusAllowed || ds[2].Status != StatusMixed || ds[2].Override != ActionBlock || ds[3].Domain != "www.lemonde.fr" ||
		ds[3].Status != "" || ds[3].Queries != 0 {
		t.Fatalf("domains %+v %+v %+v %+v", ds[0], ds[1], ds[2], ds[3])
	}
	if len(ds[0].Apps) != 1 || ds[0].Apps[0].Package != "com.example.news" || len(ds[1].Apps) != 0 {
		t.Fatalf("apps of domains %+v %+v", ds[0].Apps, ds[1].Apps)
	}
	tot, pubs := Summary(in, ds)
	if tot.Queries != 160 || tot.Blocked != 105 || tot.Allowed != 55 {
		t.Fatalf("totals %+v", tot)
	}
	g := pubs[0]
	if g.Key != "google" || g.Queries != 150 || g.Blocked != 100 || g.Domains != 2 || g.Apps != 1 || g.RxBytes != 3000 || g.TxBytes != 300 {
		t.Fatalf("google %+v", g)
	}
	o := pubs[len(pubs)-1]
	if o.Key != Other || o.Domains != 1 || o.RxBytes != 1000 || o.Queries != 0 {
		t.Fatalf("other %+v", o)
	}
	apps := Apps(in, ds, "")
	if len(apps) != 3 || apps[0].Package != "com.example.news" || apps[0].Queries != 40 || apps[0].Blocked != 30 || apps[0].Allowed != 0 ||
		apps[1].Package != "com.instagram.android" || apps[1].Blocked != 4 || apps[1].Allowed != 4 || apps[1].Label != "Instagram" ||
		apps[2].Package != "com.spotify.music" || apps[2].Queries != 0 || apps[2].RxBytes != 9000 {
		t.Fatalf("apps %+v", apps)
	}
	if meta := Apps(in, ds, "meta"); len(meta) != 1 || meta[0].Package != "com.instagram.android" {
		t.Fatalf("apps of meta %+v", meta)
	}
	// Without AdGuard: net.dns occurrences, no status.
	in.AdGuard = false
	ds = Domains(in)
	if ds[0].Domain != "app-measurement.com" || ds[0].Queries != 30 || ds[0].Status != "" || ds[0].Blocked != 0 {
		t.Fatalf("without adguard %+v", ds[0])
	}
}
