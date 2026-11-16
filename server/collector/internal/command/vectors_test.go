package command

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// The hard cases signed by the real console code (TypeScript, WebCrypto) — accents, emojis, quotes, line
// feeds, bidirectional text, non-ASCII or decomposed command codes — pass the strict validation of the
// collector and verify with the key derived here. The file is pinned on the console side
// (server/console/src/lib/commandVectors.test.ts) and replayed by the agent's Kotlin verifier.
func TestConsoleVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../console/src/lib/fixtures/command-vectors.json")
	if err != nil {
		t.Fatalf("jeu d'essai de la console introuvable : %v", err)
	}
	var vectors []struct {
		Name     string  `json:"name"`
		Code     *string `json:"code"`
		DeviceID string  `json:"device_id"`
		Type     string  `json:"type"`
		NowMS    int64   `json:"now_ms"`
		Payload  string  `json:"payload"`
		Sig      *string `json:"sig"`
		Expect   struct {
			Message *string `json:"message"`
		} `json:"expect"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) < 12 {
		t.Fatalf("%d cas seulement", len(vectors))
	}
	keys := map[string][]byte{}
	signed := 0
	for _, v := range vectors {
		p, err := Parse(v.Payload)
		if err != nil {
			t.Errorf("%s : payload refusé par le collecteur : %v", v.Name, err)
			continue
		}
		if p.Type != v.Type || p.DeviceID != v.DeviceID {
			t.Errorf("%s : type ou appareil lus différemment (%s, %s)", v.Name, p.Type, p.DeviceID)
		}
		if err := p.CheckTime(time.UnixMilli(v.NowMS).Add(time.Second)); err != nil {
			t.Errorf("%s : %v", v.Name, err)
		}
		if Sensitive(v.Type) != (v.Sig != nil) {
			t.Errorf("%s : signature présente = %v pour le type %s", v.Name, v.Sig != nil, v.Type)
		}
		if v.Sig == nil {
			continue
		}
		signed++
		if !ValidSignatureFormat(*v.Sig) {
			t.Errorf("%s : format de signature refusé", v.Name)
		}
		k, ok := keys[*v.Code]
		if !ok {
			if k, err = DeriveKey(*v.Code, v.DeviceID); err != nil {
				t.Fatal(err)
			}
			keys[*v.Code] = k
		}
		if got := Sign(k, v.Payload); got != *v.Sig {
			t.Errorf("%s : signature Go %s ≠ signature de la console %s", v.Name, got, *v.Sig)
		}
		if !Verify(k, v.Payload, *v.Sig) {
			t.Errorf("%s : signature de la console refusée", v.Name)
		}
		// The message read by the collector is the one that was typed (the agent trims it; an all-blank
		// message is not sent at all).
		m, has := p.Params["message"].(string)
		if has != (v.Expect.Message != nil) || (has && strings.TrimSpace(m) != *v.Expect.Message) {
			t.Errorf("%s : message lu %q", v.Name, m)
		}
	}
	if signed < 9 {
		t.Fatalf("%d cas signés seulement", signed)
	}
}
