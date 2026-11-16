// Package model defines the Vigie event format (contract §1) and its validation.
package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// Limits applied to a single event.
const (
	MaxEventBytes  = 256 << 10 // raw JSON size of one event
	MaxDataDepth   = 16        // nesting depth inside data
	MaxTypeLen     = 64
	MaxBootIDLen   = 128
	MaxFutureSkew  = 24 * time.Hour
	TimeFormat     = "2006-01-02T15:04:05.000Z07:00"
	minAcceptedTS  = 946684800000 // 2000-01-01T00:00:00Z in ms
	maxSafeInteger = 1<<53 - 1
)

// Rejection reasons returned to the agent (contract §3, "rejected[].reason").
const (
	ReasonInvalidJSON = "invalid_json"
	ReasonInvalidID   = "invalid_id"
	ReasonInvalidTS   = "invalid_ts"
	ReasonInvalidSeq  = "invalid_seq"
	ReasonInvalidBoot = "invalid_boot_id"
	ReasonInvalidElap = "invalid_elapsed_ms"
	ReasonInvalidType = "invalid_type"
	ReasonInvalidSev  = "invalid_sev"
	ReasonInvalidData = "invalid_data"
	ReasonTooLarge    = "too_large"
	ReasonDuplicateIn = "duplicate_in_batch" // never surfaced: counted as duplicate
)

var (
	typeRe   = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)+$`)
	ulidRe   = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
	bootIDRe = regexp.MustCompile(`^[\x21-\x7e]+$`)
)

// Event is a validated, normalized event.
type Event struct {
	ID        string          `json:"id"`
	TS        time.Time       `json:"-"`
	Seq       int64           `json:"seq"`
	BootID    string          `json:"boot_id"`
	ElapsedMS int64           `json:"elapsed_ms"`
	Type      string          `json:"type"`
	Sev       int             `json:"sev"`
	Data      json.RawMessage `json:"data"` // canonical compact JSON object
	// Decoded holds the decoded data object (json.Number for numbers).
	Decoded map[string]any `json:"-"`
}

// Domain returns the part of the type before the first dot.
func Domain(t string) string {
	if i := strings.IndexByte(t, '.'); i > 0 {
		return t[:i]
	}
	return t
}

// ValidType reports whether t is a syntactically valid event type.
func ValidType(t string) bool {
	return len(t) <= MaxTypeLen && typeRe.MatchString(t)
}

// FormatTS formats a time as RFC 3339 UTC with milliseconds.
func FormatTS(t time.Time) string { return t.UTC().Format(TimeFormat) }

// FormatMS formats unix milliseconds as RFC 3339 UTC with milliseconds.
func FormatMS(ms int64) string { return FormatTS(time.UnixMilli(ms)) }

// ValidationError carries a contract rejection reason.
type ValidationError struct {
	ID     string
	Reason string
	Detail string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Reason, e.Detail)
}

// ParseEvent validates one raw event. now is used to bound timestamps.
// On failure it returns a *ValidationError whose ID is the event id when it could be read.
func ParseEvent(raw json.RawMessage, now time.Time) (*Event, error) {
	fail := func(id, reason, detail string) (*Event, error) {
		return nil, &ValidationError{ID: id, Reason: reason, Detail: detail}
	}
	if len(raw) > MaxEventBytes {
		return fail(peekID(raw), ReasonTooLarge, "event exceeds size limit")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil {
		// peekID reads the id even when the value is too deeply nested for encoding/json.
		return fail(peekID(raw), ReasonInvalidJSON, "event is not a JSON object")
	}
	var ev Event

	// id
	var id string
	if err := json.Unmarshal(fields["id"], &id); err != nil {
		return fail("", ReasonInvalidID, "missing or non-string id")
	}
	id = strings.ToUpper(id)
	if !ulidRe.MatchString(id) {
		return fail(truncate(id, 64), ReasonInvalidID, "id is not a ULID")
	}
	ev.ID = id

	// ts
	var tsStr string
	if err := json.Unmarshal(fields["ts"], &tsStr); err != nil || len(tsStr) > 40 {
		return fail(id, ReasonInvalidTS, "missing or non-string ts")
	}
	ts, err := time.Parse(time.RFC3339Nano, tsStr)
	if err != nil {
		return fail(id, ReasonInvalidTS, "ts is not RFC 3339")
	}
	ts = ts.UTC().Truncate(time.Millisecond)
	if ts.UnixMilli() < minAcceptedTS || ts.After(now.Add(MaxFutureSkew)) {
		return fail(id, ReasonInvalidTS, "ts out of accepted range")
	}
	ev.TS = ts

	// seq, elapsed_ms
	seq, ok := parseInt(fields["seq"])
	if !ok || seq < 0 {
		return fail(id, ReasonInvalidSeq, "seq must be a non-negative integer")
	}
	ev.Seq = seq
	el, ok := parseInt(fields["elapsed_ms"])
	if !ok || el < 0 {
		return fail(id, ReasonInvalidElap, "elapsed_ms must be a non-negative integer")
	}
	ev.ElapsedMS = el

	// boot_id
	var boot string
	if err := json.Unmarshal(fields["boot_id"], &boot); err != nil || boot == "" ||
		len(boot) > MaxBootIDLen || !bootIDRe.MatchString(boot) {
		return fail(id, ReasonInvalidBoot, "boot_id must be a short printable string")
	}
	ev.BootID = boot

	// type
	var typ string
	if err := json.Unmarshal(fields["type"], &typ); err != nil || !ValidType(typ) {
		return fail(id, ReasonInvalidType, "type must match <domain>.<name> in [a-z0-9_.]")
	}
	ev.Type = typ

	// sev
	sev, ok := parseInt(fields["sev"])
	if !ok || sev < 0 || sev > 3 {
		return fail(id, ReasonInvalidSev, "sev must be 0..3")
	}
	ev.Sev = int(sev)

	// data
	rawData, present := fields["data"]
	if !present || isJSONNull(rawData) {
		rawData = json.RawMessage(`{}`)
	}
	dec := json.NewDecoder(bytes.NewReader(rawData))
	dec.UseNumber()
	var data map[string]any
	if err := dec.Decode(&data); err != nil || data == nil {
		return fail(id, ReasonInvalidData, "data must be a JSON object")
	}
	if Depth(data) > MaxDataDepth {
		return fail(id, ReasonInvalidData, "data is nested too deeply")
	}
	canon, err := Marshal(data)
	if err != nil {
		return fail(id, ReasonInvalidData, "data cannot be encoded")
	}
	ev.Data = canon
	ev.Decoded = data
	return &ev, nil
}

// Marshal encodes v as compact JSON without HTML escaping.
func Marshal(v any) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(buf.Bytes(), "\n"), nil
}

// Depth returns the nesting depth of a decoded JSON value (scalars have depth 0).
func Depth(v any) int {
	switch t := v.(type) {
	case map[string]any:
		m := 0
		for _, x := range t {
			if d := Depth(x); d > m {
				m = d
			}
		}
		return m + 1
	case []any:
		m := 0
		for _, x := range t {
			if d := Depth(x); d > m {
				m = d
			}
		}
		return m + 1
	default:
		return 0
	}
}

// parseInt accepts only JSON integers (no strings, no fractions) within the safe range.
func parseInt(raw json.RawMessage) (int64, bool) {
	raw = bytes.TrimSpace(raw)
	// Only a JSON number literal (json.Number would also accept a quoted string).
	if len(raw) == 0 || !(raw[0] == '-' || (raw[0] >= '0' && raw[0] <= '9')) {
		return 0, false
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var n json.Number
	if err := dec.Decode(&n); err != nil {
		return 0, false
	}
	i, err := n.Int64()
	if err != nil || i > maxSafeInteger || i < -maxSafeInteger {
		return 0, false
	}
	return i, true
}

func isJSONNull(raw json.RawMessage) bool {
	return string(bytes.TrimSpace(raw)) == "null"
}

// peekID extracts the id of an oversized event without decoding all of it.
func peekID(raw json.RawMessage) string {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return ""
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return ""
		}
		if k == "id" {
			var id string
			if dec.Decode(&id) == nil {
				return truncate(strings.ToUpper(id), 64)
			}
			return ""
		}
		if SkipValue(dec) != nil {
			return ""
		}
	}
	return ""
}

// SkipValue consumes one JSON value from dec with no nesting limit (Decoder.Decode refuses beyond 10000
// levels, Token does not), so that a pathological value stays confined to the event that carries it.
func SkipValue(dec *json.Decoder) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok || d == '}' || d == ']' {
		return nil
	}
	for depth := 1; depth > 0; {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok {
			if d == '{' || d == '[' {
				depth++
			} else {
				depth--
			}
		}
	}
	return nil
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// ErrNotFound is returned by lookups that find nothing.
var ErrNotFound = errors.New("not found")

// Helpers to read decoded data fields.

// Str returns m[k] as a string.
func Str(m map[string]any, k string) (string, bool) {
	s, ok := m[k].(string)
	return s, ok
}

// Num returns m[k] as a float64.
func Num(m map[string]any, k string) (float64, bool) {
	switch v := m[k].(type) {
	case json.Number:
		f, err := v.Float64()
		return f, err == nil
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	}
	return 0, false
}

// Int returns m[k] as an int64 (accepting integral floats).
func Int(m map[string]any, k string) (int64, bool) {
	switch v := m[k].(type) {
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i, true
		}
		if f, err := v.Float64(); err == nil && f == float64(int64(f)) {
			return int64(f), true
		}
	case float64:
		if v == float64(int64(v)) {
			return int64(v), true
		}
	case int:
		return int64(v), true
	case int64:
		return v, true
	}
	return 0, false
}

// Bool returns m[k] as a bool.
func Bool(m map[string]any, k string) (bool, bool) {
	b, ok := m[k].(bool)
	return b, ok
}
