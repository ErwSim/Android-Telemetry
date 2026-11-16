package tracking

import (
	"math"
	"sort"
)

// DomainCount is the AdGuard Home query log aggregated for one domain over a period.
type DomainCount struct {
	Queries int64
	Blocked int64
	Reason  string
}

// AppDomain is the number of net.dns lookups of one domain by one application over a period.
type AppDomain struct {
	Package string
	Domain  string
	Count   int64
}

// Bytes are the bytes received and sent by one application over a period (net.usage).
type Bytes struct{ Rx, Tx int64 }

// Input gathers the aggregates the view is built from.
type Input struct {
	// AdGuard is true when the AdGuard Home aggregates are used (configured); AdGuardCounts may be empty.
	AdGuard       bool
	AdGuardCounts map[string]DomainCount
	DNS           []AppDomain
	Usage         map[string]Bytes
	Overrides     map[string]string // domain -> block/allow (managed block)
	Labels        map[string]string // package -> label (latest inventory)
	Classifier    *Classifier
}

// Domain statuses.
const (
	StatusBlocked = "blocked"
	StatusAllowed = "allowed"
	StatusMixed   = "mixed"
)

// AppCount is one application that looked a domain up.
type AppCount struct {
	Package string `json:"package"`
	Count   int64  `json:"count"`
}

// Domain is one entry of GET /tracking/domains.
type Domain struct {
	Domain    string     `json:"domain"`
	Publisher string     `json:"publisher"`
	Queries   int64      `json:"queries"`
	Blocked   int64      `json:"blocked"`
	Allowed   int64      `json:"allowed"`
	Status    string     `json:"status,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	Override  string     `json:"override,omitempty"`
	Apps      []AppCount `json:"apps"`

	dnsCount int64
	ratio    float64 // blocked / queries, or -1 without AdGuard data
}

// MaxDomainApps bounds the applications listed per domain.
const MaxDomainApps = 10

// Domains builds every domain of the period, sorted by decreasing queries then name. With AdGuard, the
// counts are those of the AdGuard query log and domains seen only in net.dns have zero queries and no
// status; without AdGuard, queries are the net.dns occurrences and there is no status.
func Domains(in *Input) []*Domain {
	byName := map[string]*Domain{}
	get := func(name string) *Domain {
		d := byName[name]
		if d == nil {
			d = &Domain{Domain: name, Publisher: in.Classifier.Classify(name), Apps: []AppCount{}, ratio: -1}
			byName[name] = d
		}
		return d
	}
	if in.AdGuard {
		for name, c := range in.AdGuardCounts {
			d := get(name)
			d.Queries, d.Blocked, d.Allowed, d.Reason = c.Queries, c.Blocked, c.Queries-c.Blocked, c.Reason
			if c.Queries > 0 {
				d.ratio = float64(c.Blocked) / float64(c.Queries)
				switch {
				case c.Blocked == 0:
					d.Status = StatusAllowed
				case c.Blocked >= c.Queries:
					d.Status = StatusBlocked
				default:
					d.Status = StatusMixed
				}
			}
		}
	}
	apps := map[string]map[string]int64{}
	for _, r := range in.DNS {
		d := get(r.Domain)
		d.dnsCount += r.Count
		if r.Package != "" {
			if apps[r.Domain] == nil {
				apps[r.Domain] = map[string]int64{}
			}
			apps[r.Domain][r.Package] += r.Count
		}
	}
	out := make([]*Domain, 0, len(byName))
	for name, d := range byName {
		if !in.AdGuard {
			d.Queries = d.dnsCount
		}
		if o := in.Overrides[name]; o != "" {
			d.Override = o
		}
		for p, c := range apps[name] {
			d.Apps = append(d.Apps, AppCount{Package: p, Count: c})
		}
		sort.Slice(d.Apps, func(i, j int) bool {
			if d.Apps[i].Count != d.Apps[j].Count {
				return d.Apps[i].Count > d.Apps[j].Count
			}
			return d.Apps[i].Package < d.Apps[j].Package
		})
		if len(d.Apps) > MaxDomainApps {
			d.Apps = d.Apps[:MaxDomainApps]
		}
		out = append(out, d)
	}
	SortDomains(out)
	return out
}

// SortDomains sorts by decreasing queries, then by name (the cursor order of /tracking/domains).
func SortDomains(ds []*Domain) {
	sort.Slice(ds, func(i, j int) bool { return Before(ds[i].Queries, ds[i].Domain, ds[j].Queries, ds[j].Domain) })
}

// Before reports whether (qa, a) comes before (qb, b) in the domains order.
func Before(qa int64, a string, qb int64, b string) bool {
	if qa != qb {
		return qa > qb
	}
	return a < b
}

// Totals are the counts of the whole period.
type Totals struct {
	Queries int64 `json:"queries"`
	Blocked int64 `json:"blocked"`
	Allowed int64 `json:"allowed"`
}

// PublisherSummary is one entry of GET /tracking/summary.
type PublisherSummary struct {
	Key     string `json:"key"`
	Name    string `json:"name"`
	Queries int64  `json:"queries"`
	Blocked int64  `json:"blocked"`
	Allowed int64  `json:"allowed"`
	Domains int    `json:"domains"`
	Apps    int    `json:"apps"`
	TxBytes int64  `json:"tx_bytes"`
	RxBytes int64  `json:"rx_bytes"`
}

// Summary aggregates the domains by publisher (every publisher listed, in the order of the file).
// Bytes are an estimate: the bytes of each application (net.usage) are shared among publishers in
// proportion to its DNS lookups of their domains (the content and volume per destination are not visible).
func Summary(in *Input, domains []*Domain) (Totals, []PublisherSummary) {
	var tot Totals
	idx := map[string]*PublisherSummary{}
	pubs := make([]PublisherSummary, 0, len(in.Classifier.Publishers()))
	for _, p := range in.Classifier.Publishers() {
		pubs = append(pubs, PublisherSummary{Key: p.Key, Name: p.Name})
	}
	for i := range pubs {
		idx[pubs[i].Key] = &pubs[i]
	}
	pubOf := map[string]string{}
	for _, d := range domains {
		pubOf[d.Domain] = d.Publisher
		ps := idx[d.Publisher]
		ps.Queries += d.Queries
		ps.Blocked += d.Blocked
		ps.Allowed += d.Allowed
		ps.Domains++
		tot.Queries += d.Queries
		tot.Blocked += d.Blocked
		tot.Allowed += d.Allowed
	}
	appPub := map[string]map[string]int64{} // package -> publisher -> lookups
	appTotal := map[string]int64{}
	for _, r := range in.DNS {
		if r.Package == "" {
			continue
		}
		p := pubOf[r.Domain]
		if p == "" {
			p = in.Classifier.Classify(r.Domain)
		}
		if appPub[r.Package] == nil {
			appPub[r.Package] = map[string]int64{}
		}
		appPub[r.Package][p] += r.Count
		appTotal[r.Package] += r.Count
	}
	for pkg, byPub := range appPub {
		u := in.Usage[pkg]
		for p, n := range byPub {
			ps := idx[p]
			if ps == nil {
				continue
			}
			ps.Apps++
			if appTotal[pkg] > 0 {
				share := float64(n) / float64(appTotal[pkg])
				ps.RxBytes += int64(math.Round(float64(u.Rx) * share))
				ps.TxBytes += int64(math.Round(float64(u.Tx) * share))
			}
		}
	}
	return tot, pubs
}

// TopDomain is one of the most looked-up domains of an application.
type TopDomain struct {
	Domain string `json:"domain"`
	Count  int64  `json:"count"`
	Status string `json:"status,omitempty"`
}

// App is one entry of GET /tracking/apps.
type App struct {
	Package    string      `json:"package"`
	Label      string      `json:"label,omitempty"`
	Queries    int64       `json:"queries"`
	Blocked    int64       `json:"blocked"`
	Allowed    int64       `json:"allowed"`
	TxBytes    int64       `json:"tx_bytes"`
	RxBytes    int64       `json:"rx_bytes"`
	TopDomains []TopDomain `json:"top_domains"`
}

// MaxAppDomains bounds the top domains listed per application.
const MaxAppDomains = 5

// Apps builds the applications view: queries are the net.dns lookups of the application (restricted to
// the domains of publisher when set); blocked and allowed share those lookups according to the AdGuard
// outcome of each domain over the period (an estimate: AdGuard does not know the application), domains
// without AdGuard data counting in neither. Bytes are the application's totals (net.usage). Without a
// publisher filter, applications with traffic but no DNS lookup are listed too.
func Apps(in *Input, domains []*Domain, publisher string) []App {
	byName := map[string]*Domain{}
	for _, d := range domains {
		byName[d.Domain] = d
	}
	type acc struct {
		app  App
		doms map[string]int64
	}
	all := map[string]*acc{}
	get := func(pkg string) *acc {
		a := all[pkg]
		if a == nil {
			a = &acc{app: App{Package: pkg, Label: in.Labels[pkg], TopDomains: []TopDomain{}}, doms: map[string]int64{}}
			u := in.Usage[pkg]
			a.app.RxBytes, a.app.TxBytes = u.Rx, u.Tx
			all[pkg] = a
		}
		return a
	}
	for _, r := range in.DNS {
		if r.Package == "" {
			continue
		}
		d := byName[r.Domain]
		pub := in.Classifier.Classify(r.Domain)
		if d != nil {
			pub = d.Publisher
		}
		if publisher != "" && pub != publisher {
			continue
		}
		a := get(r.Package)
		a.app.Queries += r.Count
		a.doms[r.Domain] += r.Count
	}
	if publisher == "" {
		for pkg, u := range in.Usage {
			if pkg != "" && (u.Rx > 0 || u.Tx > 0) {
				get(pkg)
			}
		}
	}
	out := make([]App, 0, len(all))
	for _, a := range all {
		for dom, n := range a.doms {
			d := byName[dom]
			status := ""
			if d != nil && d.ratio >= 0 {
				b := int64(math.Round(float64(n) * d.ratio))
				a.app.Blocked += b
				a.app.Allowed += n - b
				status = d.Status
			}
			a.app.TopDomains = append(a.app.TopDomains, TopDomain{Domain: dom, Count: n, Status: status})
		}
		sort.Slice(a.app.TopDomains, func(i, j int) bool {
			x, y := a.app.TopDomains[i], a.app.TopDomains[j]
			if x.Count != y.Count {
				return x.Count > y.Count
			}
			return x.Domain < y.Domain
		})
		if len(a.app.TopDomains) > MaxAppDomains {
			a.app.TopDomains = a.app.TopDomains[:MaxAppDomains]
		}
		out = append(out, a.app)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Queries != out[j].Queries {
			return out[i].Queries > out[j].Queries
		}
		if bi, bj := out[i].RxBytes+out[i].TxBytes, out[j].RxBytes+out[j].TxBytes; bi != bj {
			return bi > bj
		}
		return out[i].Package < out[j].Package
	})
	return out
}
