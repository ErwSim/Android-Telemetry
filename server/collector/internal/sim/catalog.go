package sim

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// app is one installed package of the simulated phone.
type app struct {
	pkg       string
	label     string
	uid       int
	system    bool
	installer string
	version   string
	code      int
	target    int
	dangerous []string
	hosts     []string // hostnames contacted
	fgWeight  int      // likelihood to be in foreground (user apps)
	bgPerHour float64  // background DNS lookups per hour
	notifies  bool
}

var apps = []app{
	// Google
	{pkg: "com.google.android.gms", label: "Google Play services", uid: 10151, system: true, installer: "com.android.vending", version: "25.44.32", code: 254432035, target: 36,
		dangerous: []string{"android.permission.ACCESS_FINE_LOCATION", "android.permission.READ_CONTACTS", "android.permission.CAMERA"},
		hosts: []string{"play.googleapis.com", "android.clients.google.com", "www.googleapis.com", "mtalk.google.com", "app-measurement.com",
			"firebaselogging-pa.googleapis.com", "play-services-telemetry.googleapis.com", "connectivitycheck.gstatic.com", "oauth2.googleapis.com",
			"clientservices.googleapis.com", "update.googleapis.com", "people-pa.googleapis.com", "fcmatch.google.com", "lpa.ds.gsma.com"},
		bgPerHour: 70},
	{pkg: "com.android.vending", label: "Google Play Store", uid: 10152, system: true, installer: "", version: "48.6.19", code: 84861900, target: 36,
		hosts: []string{"play-fe.googleapis.com", "play-lh.googleusercontent.com", "android.clients.google.com", "play.googleapis.com"}, bgPerHour: 6, fgWeight: 1},
	{pkg: "com.google.android.googlequicksearchbox", label: "Google", uid: 10160, system: true, installer: "com.android.vending", version: "16.44.40", code: 301430543, target: 36,
		dangerous: []string{"android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"},
		hosts:     []string{"www.google.com", "www.gstatic.com", "android.googleapis.com", "app-measurement.com"}, bgPerHour: 5, fgWeight: 2},
	{pkg: "com.google.android.youtube", label: "YouTube", uid: 10233, system: true, installer: "com.android.vending", version: "20.44.38", code: 1553729984, target: 35,
		hosts: []string{"youtubei.googleapis.com", "rr3---sn-25ge7nsk.googlevideo.com", "i.ytimg.com", "yt3.ggpht.com", "www.youtube.com"}, bgPerHour: 1, fgWeight: 6},
	{pkg: "com.android.chrome", label: "Chrome", uid: 10180, system: true, installer: "com.android.vending", version: "142.0.7444.102", code: 744410233, target: 36,
		hosts: []string{"www.google.com", "clients4.google.com", "www.dailynews.example", "en.wikipedia.org", "news.ycombinator.com", "securepubads.g.doubleclick.net", "www.googletagmanager.com", "cdn.jsdelivr.net"}, bgPerHour: 2, fgWeight: 7},
	{pkg: "com.google.android.apps.maps", label: "Maps", uid: 10171, system: true, installer: "com.android.vending", version: "25.45.02", code: 1065432014, target: 35,
		dangerous: []string{"android.permission.ACCESS_FINE_LOCATION"},
		hosts:     []string{"maps.googleapis.com", "mobilemaps-pa.googleapis.com", "khms0.googleapis.com"}, bgPerHour: 2, fgWeight: 2},
	// Samsung
	{pkg: "com.samsung.android.scloud", label: "Samsung Cloud", uid: 1000, system: true, version: "5.6.00.4", code: 560004000, target: 34,
		hosts: []string{"api.samsungcloud.com", "cs-eu.samsungcloud.com"}, bgPerHour: 4},
	{pkg: "com.sec.android.app.samsungapps", label: "Galaxy Store", uid: 10045, system: true, version: "4.6.04.4", code: 460404400, target: 34,
		hosts: []string{"galaxystore.samsungapps.com", "vas.samsungapps.com", "img.samsungapps.com"}, bgPerHour: 3},
	{pkg: "com.samsung.android.mobileservice", label: "Samsung Experience Service", uid: 10050, system: true, version: "13.7.01.7", code: 1370017000, target: 34,
		hosts: []string{"eu-auth2.samsungosp.com", "eu-api.samsungosp.com", "dc.samsungdm.com"}, bgPerHour: 3},
	{pkg: "com.samsung.android.dqagent", label: "Device Quality Agent", uid: 1000, system: true, version: "16.0.08", code: 160008, target: 36,
		hosts: []string{"dqa.samsungdm.com", "dc.samsungdm.com", "dir-apis.samsungdm.com"}, bgPerHour: 2},
	{pkg: "com.samsung.android.game.gos", label: "Game Optimizing Service", uid: 10088, system: true, version: "4.4.05.0", code: 440500000, target: 34,
		hosts: []string{"gos-api.gos-gsp.io"}, bgPerHour: 0.5},
	{pkg: "com.samsung.android.bixby.agent", label: "Bixby Voice", uid: 10092, system: true, version: "3.5.20.6", code: 352006000, target: 34,
		dangerous: []string{"android.permission.RECORD_AUDIO"},
		hosts:     []string{"bixby.samsung.com", "eu-bixby-voice.samsungapis.com"}, bgPerHour: 1},
	{pkg: "com.wssyncmldm", label: "Software update", uid: 1000, system: true, version: "4.4.08", code: 440800, target: 36,
		hosts: []string{"fota-cloud-dn.ospserver.net", "fota-apis.samsungdm.com"}, bgPerHour: 0.3},
	{pkg: "com.samsung.android.email.provider", label: "Samsung Email", uid: 10070, system: true, version: "6.2.03.2", code: 620032000, target: 34,
		hosts: []string{"imap.fastmail.com", "smtp.fastmail.com"}, bgPerHour: 4, notifies: true},
	{pkg: "com.sec.android.app.camera", label: "Camera", uid: 10060, system: true, version: "15.1.01.42", code: 1510142, target: 36,
		dangerous: []string{"android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION"}, fgWeight: 2},
	{pkg: "com.samsung.android.app.contacts", label: "Contacts", uid: 10061, system: true, version: "16.0.10.9", code: 1600109, target: 36, fgWeight: 1},
	{pkg: "com.samsung.android.dialer", label: "Phone", uid: 10062, system: true, version: "16.1.24.5", code: 1612405, target: 36, fgWeight: 1,
		dangerous: []string{"android.permission.READ_CALL_LOG", "android.permission.CALL_PHONE"}},
	{pkg: "com.samsung.android.messaging", label: "Messages", uid: 10063, system: true, version: "16.0.20.22", code: 160002022, target: 36, fgWeight: 2, notifies: true,
		dangerous: []string{"android.permission.READ_SMS", "android.permission.SEND_SMS"}},
	{pkg: "io.github.erwsim.watchpost", label: "Watchpost", uid: 10301, installer: "com.android.shell", version: "1.0.0", code: 1, target: 36,
		dangerous: []string{"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION", "android.permission.POST_NOTIFICATIONS"},
		hosts:     []string{"ingest.watchpost.example", "dns.watchpost.example"}, bgPerHour: 4},
	// User apps
	{pkg: "com.whatsapp", label: "WhatsApp", uid: 10251, installer: "com.android.vending", version: "2.25.32.74", code: 252327400, target: 35,
		dangerous: []string{"android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS"},
		hosts:     []string{"g.whatsapp.net", "mmg.whatsapp.net", "static.whatsapp.net", "media-cdg4-2.cdn.whatsapp.net"}, bgPerHour: 6, fgWeight: 8, notifies: true},
	{pkg: "org.telegram.messenger", label: "Telegram", uid: 10252, installer: "com.android.vending", version: "12.1.1", code: 61331, target: 35,
		hosts: []string{"telegram.org", "venus.web.telegram.org", "cdn4.telesco.pe"}, bgPerHour: 3, fgWeight: 3, notifies: true},
	{pkg: "com.instagram.android", label: "Instagram", uid: 10253, installer: "com.android.vending", version: "405.0.0.48.79", code: 378405120, target: 35,
		dangerous: []string{"android.permission.CAMERA"},
		hosts:     []string{"i.instagram.com", "graph.instagram.com", "scontent-cdg4-1.cdninstagram.com", "edge-chat.instagram.com", "graph.facebook.com"}, bgPerHour: 2, fgWeight: 5, notifies: true},
	{pkg: "com.spotify.music", label: "Spotify", uid: 10254, installer: "com.android.vending", version: "9.0.98.592", code: 133601390, target: 35,
		hosts: []string{"spclient.wg.spotify.com", "apresolve.spotify.com", "audio-ak.spotifycdn.com", "i.scdn.co", "api-partner.spotify.com"}, bgPerHour: 3, fgWeight: 3},
	{pkg: "com.dailynews.reader", label: "Daily News", uid: 10255, installer: "com.android.vending", version: "9.29.1", code: 92901, target: 35,
		hosts: []string{"apps.dailynews.example", "img.dailynews.example", "sb.scorecardresearch.com", "securepubads.g.doubleclick.net", "cdn.privacy-mgmt.com", "app-measurement.com"}, bgPerHour: 0.5, fgWeight: 3, notifies: true},
	{pkg: "com.citytransit.app", label: "City Transit", uid: 10256, installer: "com.android.vending", version: "11.12.0", code: 111200, target: 35,
		dangerous: []string{"android.permission.ACCESS_FINE_LOCATION"},
		hosts:     []string{"api.citytransit.example", "firebaseinstallations.googleapis.com", "app-measurement.com"}, bgPerHour: 0.2, fgWeight: 2},
	{pkg: "com.railways.tickets", label: "Rail Tickets", uid: 10257, installer: "com.android.vending", version: "11.80.0", code: 118000, target: 35,
		hosts: []string{"www.railways.example", "api.railways.example", "tags.tiqcdn.com"}, bgPerHour: 0.2, fgWeight: 1},
	{pkg: "com.mybank.app", label: "My Bank", uid: 10258, installer: "com.android.vending", version: "4.24.0", code: 42400, target: 35,
		hosts: []string{"www.mybank.example", "api.mybank.example", "firebaseinstallations.googleapis.com"}, bgPerHour: 0.3, fgWeight: 1, notifies: true},
	{pkg: "org.mozilla.firefox", label: "Firefox", uid: 10259, installer: "com.android.vending", version: "145.0.1", code: 2016123451, target: 35,
		hosts: []string{"firefox.settings.services.mozilla.com", "incoming.telemetry.mozilla.org", "duckduckgo.com", "en.wikipedia.org"}, bgPerHour: 1, fgWeight: 3},
	{pkg: "org.thoughtcrime.securesms", label: "Signal", uid: 10260, installer: "com.android.vending", version: "7.62.3", code: 160703, target: 35,
		dangerous: []string{"android.permission.CAMERA", "android.permission.RECORD_AUDIO", "android.permission.READ_CONTACTS"},
		hosts:     []string{"chat.signal.org", "cdn.signal.org", "storage.signal.org"}, bgPerHour: 2, fgWeight: 3, notifies: true},
	{pkg: "com.strava", label: "Strava", uid: 10261, installer: "com.android.vending", version: "420.11", code: 1430011, target: 35,
		dangerous: []string{"android.permission.ACCESS_FINE_LOCATION", "android.permission.ACTIVITY_RECOGNITION"},
		hosts:     []string{"cdn-1.strava.com", "m.strava.com", "graphql.strava.com", "api.segment.io"}, bgPerHour: 0.5, fgWeight: 1, notifies: true},
}

func appByPkg(pkg string) *app {
	for i := range apps {
		if apps[i].pkg == pkg {
			return &apps[i]
		}
	}
	return nil
}

// hash64 returns a stable pseudo-random value derived from s.
func hash64(s string) uint64 {
	sum := sha256.Sum256([]byte(s))
	return binary.BigEndian.Uint64(sum[:8])
}

func sha256Hex(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// addressesFor returns plausible, stable resolution results for a hostname.
func addressesFor(host string) []string {
	h := hash64(host)
	b1, b2 := byte(h>>8), byte(h>>16)
	var v4prefix string
	var v6 string
	switch {
	case contains(host, "google", "gstatic", "youtube", "googlevideo", "ytimg", "ggpht", "doubleclick", "app-measurement", "googletagmanager"):
		v4prefix = []string{"142.250", "172.217", "216.58", "142.251"}[h%4]
		v6 = fmt.Sprintf("2a00:1450:4007:%x::200e", 0x800+int(b1)%32)
	case contains(host, "samsung", "ospserver", "gos-gsp"):
		v4prefix = []string{"52.29", "3.120", "18.184", "54.93"}[h%4]
	case contains(host, "whatsapp", "instagram", "facebook", "cdninstagram"):
		v4prefix = "157.240"
		v6 = fmt.Sprintf("2a03:2880:f2%02x:%x:face:b00c:0:167", int(b1)%32, int(b2)%16)
	case contains(host, "spotify", "scdn"):
		v4prefix = []string{"35.186", "34.120"}[h%2]
	case contains(host, "telegram", "telesco"):
		v4prefix = "149.154"
	case contains(host, "signal"):
		v4prefix = "13.248"
	case contains(host, "watchpost.example"):
		v4prefix = "203.0"
	default:
		v4prefix = []string{"151.101", "104.16", "23.62", "185.15"}[h%4]
	}
	out := []string{fmt.Sprintf("%s.%d.%d", v4prefix, b1, 1+int(b2)%254)}
	if h%3 == 0 {
		out = append(out, fmt.Sprintf("%s.%d.%d", v4prefix, b1, 1+int(b2+7)%254))
	}
	if v6 != "" && h%2 == 0 {
		out = append(out, v6)
	}
	return out
}

func contains(s string, subs ...string) bool {
	for _, x := range subs {
		for i := 0; i+len(x) <= len(s); i++ {
			if s[i:i+len(x)] == x {
				return true
			}
		}
	}
	return false
}

// Wi-Fi networks.
type wifiNet struct {
	ssid, bssid, security, standard string
	freq                            int
}

var (
	wifiHome   = wifiNet{ssid: "HomeNet-7A2C", bssid: "a4:3e:51:7a:2c:14", security: "WPA3-SAE", standard: "802.11ax", freq: 5180}
	wifiOffice = wifiNet{ssid: "CORP-GUEST", bssid: "f0:9f:c2:41:0a:88", security: "WPA2-PSK", standard: "802.11ac", freq: 5500}
	wifiParkAP = wifiNet{ssid: "ISP_Hotspot_secure", bssid: "68:a3:78:11:22:9e", security: "WPA2-EAP", standard: "802.11n", freq: 2437}
)

var neighborAPs = map[string][]wifiNet{
	"home": {wifiHome,
		{ssid: "Neighbor_B7A8", bssid: "00:1d:6a:b7:a8:01", security: "WPA2-PSK", freq: 2412},
		{ssid: "Router-5E21C0", bssid: "f4:ca:e5:5e:21:c0", security: "WPA2-PSK", freq: 5240},
		{ssid: "Router-91D3", bssid: "e8:ad:a6:91:d3:22", security: "WPA2-PSK", freq: 2462},
		{ssid: "DIRECT-6B-HP OfficeJet", bssid: "fa:da:0c:6b:11:20", security: "WPA2-PSK", freq: 2437},
		{ssid: "ISP_Hotspot_secure", bssid: "f4:ca:e5:5e:21:c3", security: "WPA2-EAP", freq: 2437}},
	"office": {wifiOffice,
		{ssid: "CORP", bssid: "f0:9f:c2:41:0a:80", security: "WPA2-EAP", freq: 5500},
		{ssid: "CORP", bssid: "f0:9f:c2:41:0b:80", security: "WPA2-EAP", freq: 5745},
		{ssid: "Wifi-Plaza-Open", bssid: "00:24:6c:aa:10:01", security: "OPEN", freq: 2412}},
	"park": {wifiParkAP, {ssid: "Paris_Wi-Fi", bssid: "00:0b:86:12:40:31", security: "OPEN", freq: 2412}},
}

// cellFor returns a stable serving cell for a location.
func cellFor(p latLon, salt int) map[string]any {
	key := fmt.Sprintf("%.3f,%.3f,%d", p.lat, p.lon, salt)
	h := hash64(key)
	tech := "NR"
	if h%3 == 0 {
		tech = "LTE"
	}
	return map[string]any{
		"tech": tech, "mcc": "208", "mnc": "01", "tac": 75000 + int(h%60), "ci": 20000000 + int(h%9000000),
		"pci": int(h>>20) % 504, "band": []string{"n78", "B3", "B7", "B20", "n28"}[h%5],
		"signal_dbm": -70 - int(h>>30)%40, "roaming": false, "operator": "Example Mobile",
	}
}
