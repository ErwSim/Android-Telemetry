package sim

import (
	"math"
	"time"
)

type latLon struct{ lat, lon float64 }

// Places around Paris.
var (
	placeHome   = latLon{48.85302, 2.38095} // east Paris
	placeOffice = latLon{48.89205, 2.23705} // business district, west of Paris
	routeMetro1 = []latLon{                 // metro line, east to west
		{48.85320, 2.36920}, {48.85574, 2.36079}, {48.85740, 2.35140}, {48.85860, 2.34700}, {48.86070, 2.34090},
		{48.86370, 2.32720}, {48.86560, 2.32120}, {48.86770, 2.31400}, {48.86880, 2.30970}, {48.87170, 2.30080},
		{48.87380, 2.29500}, {48.87570, 2.28780}, {48.87810, 2.28260}, {48.88070, 2.27240}, {48.88550, 2.25840},
		{48.88860, 2.24990}, {48.89190, 2.23800},
	}
	routeHomeToStation   = []latLon{placeHome, {48.85470, 2.37600}, {48.85320, 2.36920}}
	routeStationToOffice = []latLon{{48.89190, 2.23800}, {48.89205, 2.23705}}
	routeLunchLoop       = []latLon{placeOffice, {48.89120, 2.24150}, {48.89000, 2.24480}, {48.88850, 2.24300}, {48.88960, 2.23900}, placeOffice}
	routeToPark          = []latLon{placeHome, {48.85120, 2.38800}, {48.84830, 2.39580}, {48.84150, 2.40020}, {48.83500, 2.40600}, {48.83300, 2.41400}}
	routeParkLoop        = []latLon{{48.83300, 2.41400}, {48.83080, 2.42010}, {48.82750, 2.42640}, {48.82920, 2.43300}, {48.83350, 2.43040}, {48.83500, 2.42200}, {48.83300, 2.41400}}
)

func reverse(r []latLon) []latLon {
	out := make([]latLon, len(r))
	for i := range r {
		out[i] = r[len(r)-1-i]
	}
	return out
}

func concat(rs ...[]latLon) []latLon {
	var out []latLon
	for _, r := range rs {
		out = append(out, r...)
	}
	return out
}

// Movement modes.
const (
	modeStill = "still"
	modeWalk  = "walk"
	modeMetro = "metro"
	modeBike  = "bike"
)

// segment is one part of a day plan.
type segment struct {
	start, end time.Duration // since local midnight
	place      string        // "home", "office", "park", "" when moving
	mode       string
	route      []latLon // for moving segments
	at         latLon   // for still segments
}

func hm(h, m int) time.Duration { return time.Duration(h)*time.Hour + time.Duration(m)*time.Minute }

var weekdayPlan = []segment{
	{start: 0, end: hm(8, 15), place: "home", mode: modeStill, at: placeHome},
	{start: hm(8, 15), end: hm(8, 25), mode: modeWalk, route: routeHomeToStation},
	{start: hm(8, 25), end: hm(8, 50), mode: modeMetro, route: routeMetro1},
	{start: hm(8, 50), end: hm(9, 0), mode: modeWalk, route: routeStationToOffice},
	{start: hm(9, 0), end: hm(12, 30), place: "office", mode: modeStill, at: placeOffice},
	{start: hm(12, 30), end: hm(13, 30), mode: modeWalk, route: routeLunchLoop},
	{start: hm(13, 30), end: hm(18, 0), place: "office", mode: modeStill, at: placeOffice},
	{start: hm(18, 0), end: hm(18, 10), mode: modeWalk, route: reverse(routeStationToOffice)},
	{start: hm(18, 10), end: hm(18, 35), mode: modeMetro, route: reverse(routeMetro1)},
	{start: hm(18, 35), end: hm(18, 45), mode: modeWalk, route: reverse(routeHomeToStation)},
	{start: hm(18, 45), end: hm(24, 0), place: "home", mode: modeStill, at: placeHome},
}

var weekendPlan = []segment{
	{start: 0, end: hm(14, 0), place: "home", mode: modeStill, at: placeHome},
	{start: hm(14, 0), end: hm(14, 35), mode: modeBike, route: routeToPark},
	{start: hm(14, 35), end: hm(16, 40), mode: modeWalk, route: concat(routeParkLoop, routeParkLoop[1:])},
	{start: hm(16, 40), end: hm(17, 15), mode: modeBike, route: reverse(routeToPark)},
	{start: hm(17, 15), end: hm(24, 0), place: "home", mode: modeStill, at: placeHome},
}

// awake reports whether the user is awake at local time t.
func awake(t time.Time) bool {
	d := sinceMidnight(t)
	if isWeekend(t) {
		return d >= hm(9, 0) || d < hm(0, 30)
	}
	return d >= hm(7, 0) && d < hm(23, 30)
}

func isWeekend(t time.Time) bool { return t.Weekday() == time.Saturday || t.Weekday() == time.Sunday }

func sinceMidnight(t time.Time) time.Duration {
	y, m, d := t.Date()
	return t.Sub(time.Date(y, m, d, 0, 0, 0, 0, t.Location()))
}

func planFor(t time.Time) []segment {
	if isWeekend(t) {
		return weekendPlan
	}
	return weekdayPlan
}

// segmentAt returns the plan segment at local time t and the fraction elapsed.
func segmentAt(t time.Time) (segment, float64) {
	d := sinceMidnight(t)
	for _, s := range planFor(t) {
		if d >= s.start && d < s.end {
			return s, float64(d-s.start) / float64(s.end-s.start)
		}
	}
	p := planFor(t)
	return p[len(p)-1], 1
}

const earthRadius = 6371000.0

func dist(a, b latLon) float64 {
	la1, la2 := a.lat*math.Pi/180, b.lat*math.Pi/180
	dla := la2 - la1
	dlo := (b.lon - a.lon) * math.Pi / 180
	h := math.Sin(dla/2)*math.Sin(dla/2) + math.Cos(la1)*math.Cos(la2)*math.Sin(dlo/2)*math.Sin(dlo/2)
	return 2 * earthRadius * math.Asin(math.Sqrt(h))
}

func bearing(a, b latLon) float64 {
	la1, la2 := a.lat*math.Pi/180, b.lat*math.Pi/180
	dlo := (b.lon - a.lon) * math.Pi / 180
	y := math.Sin(dlo) * math.Cos(la2)
	x := math.Cos(la1)*math.Sin(la2) - math.Sin(la1)*math.Cos(la2)*math.Cos(dlo)
	deg := math.Atan2(y, x) * 180 / math.Pi
	return math.Mod(deg+360, 360)
}

func routeLength(r []latLon) float64 {
	l := 0.0
	for i := 1; i < len(r); i++ {
		l += dist(r[i-1], r[i])
	}
	return l
}

// along returns the point at fraction f of the route and the bearing there.
func along(r []latLon, f float64) (latLon, float64) {
	if len(r) == 1 {
		return r[0], 0
	}
	target := routeLength(r) * math.Max(0, math.Min(1, f))
	for i := 1; i < len(r); i++ {
		d := dist(r[i-1], r[i])
		if target <= d || i == len(r)-1 {
			k := 0.0
			if d > 0 {
				k = math.Min(1, target/d)
			}
			p := latLon{r[i-1].lat + (r[i].lat-r[i-1].lat)*k, r[i-1].lon + (r[i].lon-r[i-1].lon)*k}
			return p, bearing(r[i-1], r[i])
		}
		target -= d
	}
	return r[len(r)-1], 0
}

// offset moves p by (north, east) meters.
func offset(p latLon, north, east float64) latLon {
	return latLon{
		lat: p.lat + north/earthRadius*180/math.Pi,
		lon: p.lon + east/(earthRadius*math.Cos(p.lat*math.Pi/180))*180/math.Pi,
	}
}
