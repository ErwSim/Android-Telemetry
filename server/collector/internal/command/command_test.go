package command

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"
)

// Test vector of contract §8 (shared with the Kotlin and TypeScript implementations).
const (
	vectorCode    = "correct horse battery staple"
	vectorDevice  = "dev_0123456789abcdef"
	vectorKey     = "05fd656216f9ae34c3be8e6afcfa857c535e9e0ef438ab6c2de7130891abdb8b"
	vectorPayload = `{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef","type":"lock","params":{"message":"Lost phone — please call +1 555 0100"},"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-23T10:00:00.000Z"}`
	vectorSig     = "VVQ7B/b3fOzaG+sWd7Fqi7NKVRzdu5L3+NEIKurMXdE="
)

func TestContractVector(t *testing.T) {
	k, err := DeriveKey(vectorCode, vectorDevice)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(k); got != vectorKey {
		t.Fatalf("K = %s, want %s", got, vectorKey)
	}
	if got := Sign(k, vectorPayload); got != vectorSig {
		t.Fatalf("sig = %s, want %s", got, vectorSig)
	}
	if !Verify(k, vectorPayload, vectorSig) {
		t.Fatal("vector signature does not verify")
	}
	if Verify(k, vectorPayload+" ", vectorSig) || Verify(k, vectorPayload, strings.Replace(vectorSig, "G", "H", 1)) {
		t.Fatal("altered payload or signature verifies")
	}
	if !ValidSignatureFormat(vectorSig) || ValidSignatureFormat(vectorSig[:43]) || ValidSignatureFormat(strings.TrimSuffix(vectorSig, "=")+"A") {
		t.Fatal("signature format check")
	}
	p, err := Parse(vectorPayload)
	if err != nil {
		t.Fatal(err)
	}
	if p.ID != "01JCQ8Z3K4M5N6P7Q8R9S0T1V2" || p.DeviceID != vectorDevice || p.Type != TypeLock || !Sensitive(p.Type) ||
		p.Params["message"] != "Lost phone — please call +1 555 0100" {
		t.Fatalf("parsed %+v", p)
	}
	if err := p.CheckTime(time.Date(2026, 11, 16, 10, 5, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	if err := p.CheckTime(time.Date(2026, 11, 16, 11, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("issued_at one hour old accepted at creation")
	}
	if err := p.CheckTime(time.Date(2026, 11, 24, 0, 0, 0, 0, time.UTC)); err == nil || err.(*Error).Code != "expired" {
		t.Fatalf("expired payload: %v", err)
	}
}

func payload(fields string) string {
	return `{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"dev_0123456789abcdef",` + fields +
		`,"issued_at":"2026-11-16T10:00:00.000Z","expires_at":"2026-11-16T11:00:00.000Z"}`
}

func TestParseRejects(t *testing.T) {
	long := strings.Repeat("ö", 201)
	cases := map[string]string{
		"unknown type":        payload(`"type":"reboot","params":{}`),
		"duplicate key":       payload(`"type":"ring","type":"wipe","params":{}`),
		"duplicate param":     payload(`"type":"ring","params":{"duration_s":5,"duration_s":500}`),
		"unknown field":       payload(`"type":"ring","params":{},"extra":1`),
		"unknown param":       payload(`"type":"ring","params":{"volume":5}`),
		"param on stop_ring":  payload(`"type":"stop_ring","params":{"duration_s":5}`),
		"duration too long":   payload(`"type":"ring","params":{"duration_s":301}`),
		"duration zero":       payload(`"type":"vibrate","params":{"duration_s":0}`),
		"vibrate too long":    payload(`"type":"vibrate","params":{"duration_s":61}`),
		"fractional duration": payload(`"type":"ring","params":{"duration_s":5.0}`),
		"string duration":     payload(`"type":"ring","params":{"duration_s":"5"}`),
		"vibrate not bool":    payload(`"type":"ring","params":{"vibrate":1}`),
		"message too long":    payload(`"type":"lock","params":{"message":"` + long + `"}`),
		"control char":        payload(`"type":"lock","params":{"message":"a\u0007b"}`),
		"params not object":   payload(`"type":"ring","params":[]`),
		"nested param":        payload(`"type":"lock","params":{"message":{"a":1}}`),
		"trailing data":       payload(`"type":"ring","params":{}`) + ` {}`,
		"v=2":                 strings.Replace(payload(`"type":"ring","params":{}`), `"v":1`, `"v":2`, 1),
		"v string":            strings.Replace(payload(`"type":"ring","params":{}`), `"v":1`, `"v":"1"`, 1),
		"lower-case id":       strings.Replace(payload(`"type":"ring","params":{}`), `01JCQ8Z3K4M5N6P7Q8R9S0T1V2`, `01jcq8z3k4m5n6p7q8r9s0t1v2`, 1),
		"not json":            `{"v":1,`,
		"array":               `[1]`,
		"invalid utf8":        payload(`"type":"lock","params":{"message":"` + "\xff" + `"}`),
		"replacement char":    payload(`"type":"lock","params":{"message":"` + "�" + `"}`),
		"expires before":      strings.Replace(payload(`"type":"ring","params":{}`), `2026-11-16T11:00:00.000Z`, `2026-11-16T09:00:00.000Z`, 1),
		"validity > 30 days":  strings.Replace(payload(`"type":"ring","params":{}`), `2026-11-16T11:00:00.000Z`, `2026-12-17T11:00:00.000Z`, 1),
		"wipe > 24 hours":     strings.Replace(payload(`"type":"wipe","params":{}`), `2026-11-16T11:00:00.000Z`, `2026-11-17T10:00:00.001Z`, 1),
		"line separator":      payload(`"type":"lock","params":{"message":"a\u2028b"}`),
		"paragraph separator": payload(`"type":"lock","params":{"message":"a` + "\u2029" + `b"}`),
		"raw line separator":  payload(`"type":"lock","params":{"message":"a` + "\u2028" + `b"}`),
		"bad date":            strings.Replace(payload(`"type":"ring","params":{}`), `2026-11-16T11:00:00.000Z`, `demain`, 1),
		"missing expires":     `{"v":1,"id":"01JCQ8Z3K4M5N6P7Q8R9S0T1V2","device_id":"d","type":"ring","issued_at":"2026-11-16T10:00:00.000Z"}`,
		"too large":           payload(`"type":"lock","params":{"message":"` + strings.Repeat(" ", MaxPayloadBytes) + `"}`),
		"deep nesting":        payload(`"type":"ring","params":{},"x":` + strings.Repeat("[", 40) + strings.Repeat("]", 40)),
	}
	for name, p := range cases {
		if _, err := Parse(p); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestParseAccepts(t *testing.T) {
	ok := []string{
		payload(`"type":"ring","params":{"duration_s":300,"vibrate":false}`),
		payload(`"type":"ring","params":{}`),
		payload(`"type":"ring"`), // params absent: no parameter
		payload(`"type":"vibrate","params":{"duration_s":1}`),
		payload(`"type":"stop_ring","params":{}`),
		payload(`"type":"locate","params":{}`),
		payload(`"type":"lock","params":{"message":"` + strings.Repeat("😀", 100) + `"}`), // 200 UTF-16 units
		payload(`"type":"lock","params":{"message":"line 1\nline 2"}`),
		payload(`"type":"lock","params":{}`),
		payload(`"type":"clear_lock_message","params":{}`),
		payload(`"type":"wipe","params":{}`),
		strings.Replace(payload(`"type":"wipe","params":{}`), `2026-11-16T11:00:00.000Z`, `2026-11-17T10:00:00.000Z`, 1), // 24 h exactly
		strings.Replace(payload(`"type":"lock","params":{}`), `2026-11-16T11:00:00.000Z`, `2026-12-16T10:00:00.000Z`, 1), // 30 days
		" " + payload(`"type":"ring","params":{}`) + "\n",
	}
	for _, p := range ok {
		if _, err := Parse(p); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if _, err := Parse(payload(`"type":"lock","params":{"message":"` + strings.Repeat("😀", 101) + `"}`)); err == nil {
		t.Error("202 UTF-16 units accepted")
	}
}
