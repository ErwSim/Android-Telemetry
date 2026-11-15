package model

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 11, 15, 21, 45, 0, 0, time.UTC)

func ev(over map[string]any) json.RawMessage {
	m := map[string]any{
		"id": "01JCQ8Z3K4M5N6P7Q8R9S0T1V2", "ts": "2026-11-15T21:43:03.974Z", "seq": 18234, "boot_id": "b7e1-42",
		"elapsed_ms": 86400123, "type": "location.fix", "sev": 0, "data": map[string]any{"lat": 48.85, "lon": 2.35},
	}
	for k, v := range over {
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
	}
	b, _ := json.Marshal(m)
	return b
}

func reason(t *testing.T, raw json.RawMessage) string {
	t.Helper()
	_, err := ParseEvent(raw, now)
	if err == nil {
		return ""
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("unexpected error type %T", err)
	}
	return ve.Reason
}

func TestParseEventValid(t *testing.T) {
	e, err := ParseEvent(ev(nil), now)
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != "01JCQ8Z3K4M5N6P7Q8R9S0T1V2" || e.Seq != 18234 || e.Type != "location.fix" || e.Sev != 0 || e.BootID != "b7e1-42" {
		t.Fatalf("bad event %+v", e)
	}
	if got := FormatTS(e.TS); got != "2026-11-15T21:43:03.974Z" {
		t.Fatalf("ts %s", got)
	}
	if string(e.Data) != `{"lat":48.85,"lon":2.35}` {
		t.Fatalf("data %s", e.Data)
	}
}

func TestParseEventNormalizes(t *testing.T) {
	// Lower-case ULID, offset timestamp, missing data, unknown top-level field.
	e, err := ParseEvent(ev(map[string]any{"id": "01jcq8z3k4m5n6p7q8r9s0t1v2", "ts": "2026-11-15T22:43:03.974+01:00",
		"data": nil, "extra": "x", "type": "future.unknown_type"}), now)
	if err != nil {
		t.Fatal(err)
	}
	if e.ID != "01JCQ8Z3K4M5N6P7Q8R9S0T1V2" || FormatTS(e.TS) != "2026-11-15T21:43:03.974Z" || string(e.Data) != "{}" {
		t.Fatalf("not normalized: %s %s %s", e.ID, FormatTS(e.TS), e.Data)
	}
}

func TestParseEventRejects(t *testing.T) {
	deep := map[string]any{}
	cur := deep
	for range MaxDataDepth + 2 {
		n := map[string]any{}
		cur["x"] = n
		cur = n
	}
	cases := map[string]struct {
		raw  json.RawMessage
		want string
	}{
		"not object":     {json.RawMessage(`[1,2]`), ReasonInvalidJSON},
		"missing id":     {ev(map[string]any{"id": nil}), ReasonInvalidID},
		"bad id":         {ev(map[string]any{"id": "not-a-ulid"}), ReasonInvalidID},
		"id overflow":    {ev(map[string]any{"id": "81JCQ8Z3K4M5N6P7Q8R9S0T1V2"}), ReasonInvalidID},
		"bad ts":         {ev(map[string]any{"ts": "yesterday"}), ReasonInvalidTS},
		"future ts":      {ev(map[string]any{"ts": "2027-01-01T00:00:00Z"}), ReasonInvalidTS},
		"ancient ts":     {ev(map[string]any{"ts": "1970-01-01T00:00:00Z"}), ReasonInvalidTS},
		"string seq":     {ev(map[string]any{"seq": "12"}), ReasonInvalidSeq},
		"float seq":      {ev(map[string]any{"seq": 1.5}), ReasonInvalidSeq},
		"negative seq":   {ev(map[string]any{"seq": -1}), ReasonInvalidSeq},
		"no boot":        {ev(map[string]any{"boot_id": ""}), ReasonInvalidBoot},
		"bad elapsed":    {ev(map[string]any{"elapsed_ms": "x"}), ReasonInvalidElap},
		"upper type":     {ev(map[string]any{"type": "Location.Fix"}), ReasonInvalidType},
		"no dot":         {ev(map[string]any{"type": "location"}), ReasonInvalidType},
		"type chars":     {ev(map[string]any{"type": "net.dns;drop"}), ReasonInvalidType},
		"sev 4":          {ev(map[string]any{"sev": 4}), ReasonInvalidSev},
		"data array":     {ev(map[string]any{"data": []int{1}}), ReasonInvalidData},
		"data string":    {ev(map[string]any{"data": "x"}), ReasonInvalidData},
		"data too deep":  {ev(map[string]any{"data": deep}), ReasonInvalidData},
		"event too big":  {ev(map[string]any{"data": map[string]any{"x": strings.Repeat("a", MaxEventBytes)}}), ReasonTooLarge},
		"long type":      {ev(map[string]any{"type": "a." + strings.Repeat("b", 70)}), ReasonInvalidType},
		"control boot":   {ev(map[string]any{"boot_id": "a\nb"}), ReasonInvalidBoot},
		"huge seq":       {ev(map[string]any{"seq": json.Number("9007199254740993")}), ReasonInvalidSeq},
		"null id":        {ev(map[string]any{"id": json.RawMessage("null")}), ReasonInvalidID},
		"numeric id":     {ev(map[string]any{"id": 12}), ReasonInvalidID},
		"missing type":   {ev(map[string]any{"type": nil}), ReasonInvalidType},
		"missing sev":    {ev(map[string]any{"sev": nil}), ReasonInvalidSev},
		"missing seq":    {ev(map[string]any{"seq": nil}), ReasonInvalidSeq},
		"missing ts":     {ev(map[string]any{"ts": nil}), ReasonInvalidTS},
		"missing boot":   {ev(map[string]any{"boot_id": nil}), ReasonInvalidBoot},
		"missing elapse": {ev(map[string]any{"elapsed_ms": nil}), ReasonInvalidElap},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			if got := reason(t, c.raw); got != c.want {
				t.Fatalf("reason = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRejectionKeepsID(t *testing.T) {
	_, err := ParseEvent(ev(map[string]any{"sev": 9}), now)
	var ve *ValidationError
	if !errors.As(err, &ve) || ve.ID != "01JCQ8Z3K4M5N6P7Q8R9S0T1V2" {
		t.Fatalf("id not reported: %v", err)
	}
	big := ev(map[string]any{"data": map[string]any{"x": strings.Repeat("a", MaxEventBytes)}})
	_, err = ParseEvent(big, now)
	if !errors.As(err, &ve) || ve.ID != "01JCQ8Z3K4M5N6P7Q8R9S0T1V2" {
		t.Fatalf("id of oversized event not reported: %v", err)
	}
}

func TestDomain(t *testing.T) {
	if Domain("net.wifi_scan.ap") != "net" || Domain("x") != "x" {
		t.Fatal("domain")
	}
}
