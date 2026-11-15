package config

import "testing"

func lookup(m map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

func TestDefaults(t *testing.T) {
	c, err := FromLookup(lookup(nil))
	if err != nil {
		t.Fatal(err)
	}
	if c.Listen != ":8080" || c.DataDir != "/data" || c.ExportMaxBytes != 52428800 || c.ExportKeep != 5 || !c.RequireClientCert ||
		c.RetentionDays != 90 || !c.CookieSecure || len(c.TrustedProxies) != 1 || c.TrustedProxies[0].String() != "127.0.0.1/32" ||
		len(c.MapTileOrigins) != 1 || c.DBPath() != "/data/vigie.db" || c.PKIDir() != "/data/pki" {
		t.Fatalf("defaults: %+v", c)
	}
}

func TestParse(t *testing.T) {
	c, err := FromLookup(lookup(map[string]string{
		"VIGIE_TRUSTED_PROXIES": "172.18.0.0/16, 10.0.0.5 ::1", "VIGIE_REQUIRE_CLIENT_CERT": "false",
		"VIGIE_MAP_TILE_ORIGINS": "https://tiles.example.org https://a.tile.example.org:8443",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(c.TrustedProxies) != 3 || c.RequireClientCert || len(c.MapTileOrigins) != 2 {
		t.Fatalf("%+v", c)
	}
}

func TestInvalid(t *testing.T) {
	for _, m := range []map[string]string{
		{"VIGIE_TRUSTED_PROXIES": "nope"},
		{"VIGIE_RETENTION_DAYS": "0"},
		{"VIGIE_EXPORT_KEEP": "x"},
		{"VIGIE_COOKIE_SECURE": "peut-être"},
		{"VIGIE_MAP_TILE_ORIGINS": "https://evil.example; script-src *"},
		{"VIGIE_MAP_TILE_ORIGINS": "http://tiles.example.org"},
	} {
		if _, err := FromLookup(lookup(m)); err == nil {
			t.Fatalf("accepted %v", m)
		}
	}
}
