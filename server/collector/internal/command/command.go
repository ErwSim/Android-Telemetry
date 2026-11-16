// Package command implements the remote commands of contract §8: the closed list of
// command types, the strict validation of the payload relayed by the collector, and
// the key derivation and signature of sensitive commands (used by the tests and the
// simulated agent: the collector itself never knows the command code).
package command

import (
	"bytes"
	"crypto/hmac"
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/erwsim/android-telemetry/server/collector/internal/model"
)

// Command types (contract §8).
const (
	TypeRing             = "ring"
	TypeVibrate          = "vibrate"
	TypeStopRing         = "stop_ring"
	TypeLocate           = "locate"
	TypeLock             = "lock"
	TypeClearLockMessage = "clear_lock_message"
	TypeWipe             = "wipe"
)

// Limits of the payload.
const (
	MaxPayloadBytes   = 4096
	MaxValidity       = 30 * 24 * time.Hour
	MaxIssueSkew      = 10 * time.Minute // |issued_at - server time| accepted at creation
	MaxMessageUnits   = 200              // lock message, in UTF-16 code units (JavaScript and Kotlin String.length)
	PBKDF2Iterations  = 600000
	KeyBytes          = 32
	SaltPrefix        = "vigie-cmd-v1:"
	SignatureEncLen   = 44 // base64 of a 32-byte HMAC-SHA256, padded
	DefaultSimpleTTL  = time.Hour
	DefaultSensitiveT = 7 * 24 * time.Hour
)

type paramKind int

const (
	pInt paramKind = iota
	pBool
	pString
)

type paramSpec struct {
	kind     paramKind
	min, max int64 // integers: bounds; strings: max UTF-16 units
}

type typeSpec struct {
	sensitive bool
	params    map[string]paramSpec
}

var specs = map[string]typeSpec{
	TypeRing:             {params: map[string]paramSpec{"duration_s": {kind: pInt, min: 1, max: 300}, "vibrate": {kind: pBool}}},
	TypeVibrate:          {params: map[string]paramSpec{"duration_s": {kind: pInt, min: 1, max: 60}}},
	TypeStopRing:         {},
	TypeLocate:           {},
	TypeLock:             {sensitive: true, params: map[string]paramSpec{"message": {kind: pString, max: MaxMessageUnits}}},
	TypeClearLockMessage: {sensitive: true},
	TypeWipe:             {sensitive: true},
}

// Types returns the closed list of command types.
func Types() []string {
	return []string{TypeRing, TypeVibrate, TypeStopRing, TypeLocate, TypeLock, TypeClearLockMessage, TypeWipe}
}

// Known reports whether t is a command type of the closed list.
func Known(t string) bool { _, ok := specs[t]; return ok }

// Sensitive reports whether commands of type t must be signed.
func Sensitive(t string) bool { return specs[t].sensitive }

// Error is a validation error with a stable code for the API.
type Error struct {
	Code string
	Msg  string
}

func (e *Error) Error() string { return e.Msg }

func fail(code, format string, a ...any) error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// Payload is the analyzed copy of a payload. The collector never re-serializes it:
// the original string is relayed byte for byte.
type Payload struct {
	ID        string
	DeviceID  string
	Type      string
	Params    map[string]any // validated parameters (absent ones are not filled in)
	IssuedAt  time.Time
	ExpiresAt time.Time
}

// Parse analyzes a payload strictly: a single JSON object, no duplicate or unknown key,
// "v" = 1, a canonical ULID "id", a known "type", parameters of the right type and within
// bounds, RFC 3339 dates with expires_at after issued_at and a validity of 30 days at most.
// The device and the current time are checked by the caller (CheckTime).
func Parse(payload string) (*Payload, error) {
	if len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return nil, fail("invalid_payload", "payload : 1 à %d octets", MaxPayloadBytes)
	}
	if !utf8.ValidString(payload) || strings.ContainsRune(payload, utf8.RuneError) {
		// U+FFFD also flags a lone surrogate replaced while decoding the request: the bytes
		// would no longer be those that were signed.
		return nil, fail("invalid_payload", "payload : UTF-8 invalide")
	}
	fields, err := StrictObject([]byte(payload))
	if err != nil {
		return nil, fail("invalid_payload", "payload : %s", err.Error())
	}
	allowed := map[string]bool{"v": true, "id": true, "device_id": true, "type": true, "params": true, "issued_at": true, "expires_at": true}
	for k := range fields {
		if !allowed[k] {
			return nil, fail("invalid_payload", "payload : champ inconnu %q", k)
		}
	}
	if v, ok := fields["v"]; !ok || string(v) != "1" {
		return nil, fail("invalid_payload", "payload : v doit valoir 1")
	}
	p := &Payload{}
	str := func(k string) (string, error) {
		raw, ok := fields[k]
		if !ok {
			return "", fail("invalid_payload", "payload : champ %s manquant", k)
		}
		var s string
		if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
			return "", fail("invalid_payload", "payload : %s doit être une chaîne", k)
		}
		return s, nil
	}
	if p.ID, err = str("id"); err != nil {
		return nil, err
	}
	if !model.ValidULID(p.ID) {
		return nil, fail("invalid_payload", "payload : id doit être un ULID (26 caractères, majuscules)")
	}
	if p.DeviceID, err = str("device_id"); err != nil {
		return nil, err
	}
	if p.Type, err = str("type"); err != nil {
		return nil, err
	}
	spec, ok := specs[p.Type]
	if !ok {
		return nil, fail("unknown_type", "type de commande inconnu (liste fermée : %s)", strings.Join(Types(), ", "))
	}
	if p.Params, err = parseParams(fields["params"], spec); err != nil {
		return nil, err
	}
	for _, k := range []string{"issued_at", "expires_at"} {
		s, err := str(k)
		if err != nil {
			return nil, err
		}
		t, perr := time.Parse(time.RFC3339Nano, s)
		if perr != nil || len(s) > 40 {
			return nil, fail("invalid_payload", "payload : %s doit être une date RFC 3339", k)
		}
		if k == "issued_at" {
			p.IssuedAt = t
		} else {
			p.ExpiresAt = t
		}
	}
	if !p.ExpiresAt.After(p.IssuedAt) {
		return nil, fail("invalid_validity", "expires_at doit suivre issued_at")
	}
	if p.ExpiresAt.Sub(p.IssuedAt) > MaxValidity {
		return nil, fail("invalid_validity", "durée de validité de 30 jours au plus")
	}
	return p, nil
}

// CheckTime verifies the payload against the server time at creation: not expired, and
// issued_at within MaxIssueSkew of now (an old signed payload cannot be replayed later).
func (p *Payload) CheckTime(now time.Time) error {
	if !p.ExpiresAt.After(now) {
		return fail("expired", "commande déjà expirée")
	}
	if d := p.IssuedAt.Sub(now); d > MaxIssueSkew || d < -MaxIssueSkew {
		return fail("invalid_validity", "issued_at doit être à moins de 10 minutes de l'heure du serveur")
	}
	return nil
}

func parseParams(raw json.RawMessage, spec typeSpec) (map[string]any, error) {
	out := map[string]any{}
	if raw == nil {
		return out, nil
	}
	fields, err := StrictObject(raw)
	if err != nil {
		return nil, fail("bad_params", "params doit être un objet JSON (%s)", err.Error())
	}
	for k, v := range fields {
		ps, ok := spec.params[k]
		if !ok {
			return nil, fail("bad_params", "paramètre inconnu %q pour ce type", k)
		}
		switch ps.kind {
		case pInt:
			n, ok := jsonInt(v)
			if !ok || n < ps.min || n > ps.max {
				return nil, fail("bad_params", "%s : entier entre %d et %d attendu", k, ps.min, ps.max)
			}
			out[k] = n
		case pBool:
			switch string(v) {
			case "true":
				out[k] = true
			case "false":
				out[k] = false
			default:
				return nil, fail("bad_params", "%s : booléen attendu", k)
			}
		case pString:
			var s string
			if len(v) == 0 || v[0] != '"' || json.Unmarshal(v, &s) != nil {
				return nil, fail("bad_params", "%s : chaîne attendue", k)
			}
			if int64(len(utf16.Encode([]rune(s)))) > ps.max {
				return nil, fail("bad_params", "%s : %d caractères au plus", k, ps.max)
			}
			for _, r := range s {
				if (unicode.IsControl(r) && r != '\n') || r == ' ' || r == ' ' {
					return nil, fail("bad_params", "%s : caractère de contrôle interdit", k)
				}
			}
			out[k] = s
		}
	}
	return out, nil
}

// jsonInt accepts an integer literal only (no fraction, exponent or string).
func jsonInt(raw json.RawMessage) (int64, bool) {
	s := string(raw)
	if s == "" || len(s) > 18 {
		return 0, false
	}
	i := 0
	if s[0] == '-' {
		i = 1
	}
	if i == len(s) {
		return 0, false
	}
	var n int64
	for ; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int64(c-'0')
	}
	if s[0] == '-' {
		n = -n
	}
	return n, true
}

// StrictObject decodes one JSON object into its raw member values, refusing duplicate keys,
// any value after the object, and objects or arrays nested deeper than 32 levels.
func StrictObject(raw []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("objet JSON attendu")
	}
	out := map[string]json.RawMessage{}
	for dec.More() {
		kt, err := dec.Token()
		if err != nil {
			return nil, errors.New("JSON invalide")
		}
		k, _ := kt.(string)
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("clé %q en double", k)
		}
		start := dec.InputOffset()
		if err := skipBounded(dec, 32); err != nil {
			return nil, errors.New("JSON invalide")
		}
		v := bytes.TrimSpace(raw[start:dec.InputOffset()])
		v = bytes.TrimSpace(bytes.TrimPrefix(v, []byte(":")))
		out[k] = json.RawMessage(v)
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return nil, errors.New("objet JSON mal terminé")
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("données après l'objet JSON")
	}
	return out, nil
}

func skipBounded(dec *json.Decoder, maxDepth int) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	d, ok := tok.(json.Delim)
	if !ok {
		return nil
	}
	if d == '}' || d == ']' {
		return errors.New("délimiteur inattendu")
	}
	for depth := 1; depth > 0; {
		if depth > maxDepth {
			return errors.New("imbrication excessive")
		}
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

// ValidSignatureFormat reports whether sig is the padded standard base64 of 32 bytes.
// The collector cannot verify the signature itself (it does not know the code).
func ValidSignatureFormat(sig string) bool {
	if len(sig) != SignatureEncLen {
		return false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(sig)
	return err == nil && len(b) == KeyBytes
}

// DeriveKey computes K = PBKDF2-HMAC-SHA256(code, "vigie-cmd-v1:" + device_id, 600000, 32).
func DeriveKey(code, deviceID string) ([]byte, error) {
	return pbkdf2.Key(sha256.New, code, []byte(SaltPrefix+deviceID), PBKDF2Iterations, KeyBytes)
}

// Sign returns base64(HMAC-SHA256(key, payload bytes)).
func Sign(key []byte, payload string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(payload))
	return base64.StdEncoding.EncodeToString(m.Sum(nil))
}

// Verify checks a signature in constant time.
func Verify(key []byte, payload, sig string) bool {
	got, err := base64.StdEncoding.Strict().DecodeString(sig)
	if err != nil {
		return false
	}
	m := hmac.New(sha256.New, key)
	m.Write([]byte(payload))
	return hmac.Equal(got, m.Sum(nil))
}

// Result statuses reported by the agent.
const (
	StatusExecuted = "executed"
	StatusFailed   = "failed"
	StatusRefused  = "refused"
)

// ValidResultStatus reports whether s is a status the agent may report.
func ValidResultStatus(s string) bool {
	return s == StatusExecuted || s == StatusFailed || s == StatusRefused
}

// IssuedSeverity is the severity of the command.issued event: 0 for a simple command, 1 for
// lock and clear_lock_message, 2 for wipe.
func IssuedSeverity(t string) int {
	switch {
	case t == TypeWipe:
		return 2
	case Sensitive(t):
		return 1
	}
	return 0
}

// ResultSeverity mirrors the severity rule of command.result (contract §8): 0 for a simple
// command executed, 2 for lock or wipe executed, 3 for bad_signature and locked_out, 1 otherwise.
func ResultSeverity(t, status, detail string) int {
	switch status {
	case StatusExecuted:
		switch {
		case t == TypeLock || t == TypeWipe:
			return 2
		case Sensitive(t):
			return 1
		}
		return 0
	case StatusRefused:
		if detail == "bad_signature" || detail == "locked_out" {
			return 3
		}
	}
	return 1
}
