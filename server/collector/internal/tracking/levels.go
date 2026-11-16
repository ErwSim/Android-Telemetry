package tracking

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
)

// Blocking levels (contract §9), in display order.
var LevelKeys = []string{"permissif", "equilibre", "strict"}

// ListDef is one AdGuard Home filter list managed by the levels file.
type ListDef struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Allowlist bool   `json:"allowlist,omitempty"`
}

// Level is one blocking level.
type Level struct {
	Key         string   `json:"key"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Lists       []string `json:"lists"`
}

// Levels is the content of VIGIE_ADGUARD_LEVELS_FILE (format documented in the README).
type Levels struct {
	Version int                `json:"version"`
	Lists   map[string]ListDef `json:"lists"`
	Levels  []Level            `json:"levels"`
}

// LevelInfo is the public description of a level.
type LevelInfo struct {
	Key         string `json:"key"`
	Name        string `json:"name"`
	Description string `json:"description"`
}

var listIDRe = regexp.MustCompile(`^[a-z0-9_-]{1,64}$`)

// LoadLevels reads and validates a levels file.
func LoadLevels(path string) (*Levels, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	if len(b) > 1<<20 {
		return nil, errors.New("fichier de niveaux supérieur à 1 Mio")
	}
	return ParseLevels(b)
}

func printable(s string, max int, allowEmpty bool) bool {
	if len(s) > max || (!allowEmpty && strings.TrimSpace(s) == "") {
		return false
	}
	return strings.IndexFunc(s, unicode.IsControl) < 0
}

// ParseLevels validates the levels file: version 1, lists identified by [a-z0-9_-]{1,64} with a name and
// an http(s) URL or an absolute path (each URL once), exactly the three levels permissif, equilibre and
// strict, each naming existing lists. Unknown fields are refused.
func ParseLevels(b []byte) (*Levels, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	var l Levels
	if err := dec.Decode(&l); err != nil {
		return nil, fmt.Errorf("fichier de niveaux illisible : %w", err)
	}
	if l.Version != 1 {
		return nil, errors.New("fichier de niveaux : version 1 attendue")
	}
	urls := map[string]string{}
	for id, def := range l.Lists {
		if !listIDRe.MatchString(id) {
			return nil, fmt.Errorf("liste %q : identifiant [a-z0-9_-]{1,64} attendu", id)
		}
		if !printable(def.Name, 128, false) {
			return nil, fmt.Errorf("liste %q : nom de 1 à 128 caractères imprimables attendu", id)
		}
		if !validListURL(def.URL) {
			return nil, fmt.Errorf("liste %q : URL http(s):// ou chemin absolu attendu", id)
		}
		if prev, dup := urls[def.URL]; dup {
			return nil, fmt.Errorf("listes %q et %q : même URL", prev, id)
		}
		urls[def.URL] = id
	}
	if len(l.Levels) != len(LevelKeys) {
		return nil, fmt.Errorf("fichier de niveaux : exactement les niveaux %s attendus", strings.Join(LevelKeys, ", "))
	}
	seen := map[string]bool{}
	for _, lv := range l.Levels {
		known := false
		for _, k := range LevelKeys {
			known = known || k == lv.Key
		}
		if !known || seen[lv.Key] {
			return nil, fmt.Errorf("niveau %q inconnu ou en double (attendus : %s)", lv.Key, strings.Join(LevelKeys, ", "))
		}
		seen[lv.Key] = true
		if !printable(lv.Name, 64, false) || !printable(lv.Description, 500, true) {
			return nil, fmt.Errorf("niveau %q : nom (64) ou description (500) invalide", lv.Key)
		}
		inLevel := map[string]bool{}
		for _, id := range lv.Lists {
			if _, ok := l.Lists[id]; !ok || inLevel[id] {
				return nil, fmt.Errorf("niveau %q : liste %q inconnue ou en double", lv.Key, id)
			}
			inLevel[id] = true
		}
	}
	return &l, nil
}

func validListURL(u string) bool {
	if len(u) == 0 || len(u) > 2048 || strings.IndexFunc(u, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
		return false
	}
	if strings.HasPrefix(u, "https://") || strings.HasPrefix(u, "http://") {
		return len(u) > len("https://")
	}
	return filepath.IsAbs(u) && filepath.Clean(u) == u
}

// Infos returns the public description of the levels, in display order.
func (l *Levels) Infos() []LevelInfo {
	out := []LevelInfo{}
	if l == nil {
		return out
	}
	for _, k := range LevelKeys {
		for _, lv := range l.Levels {
			if lv.Key == k {
				out = append(out, LevelInfo{Key: lv.Key, Name: lv.Name, Description: lv.Description})
			}
		}
	}
	return out
}

// Has reports whether key is a level of the file.
func (l *Levels) Has(key string) bool { return l.level(key) != nil }

func (l *Levels) level(key string) *Level {
	if l == nil {
		return nil
	}
	for i := range l.Levels {
		if l.Levels[i].Key == key {
			return &l.Levels[i]
		}
	}
	return nil
}

// FilterState is one filter list as reported by AdGuard Home.
type FilterState struct {
	URL       string
	Name      string
	Enabled   bool
	Allowlist bool
}

func find(filters []FilterState, def ListDef) *FilterState {
	for i := range filters {
		if filters[i].URL == def.URL && filters[i].Allowlist == def.Allowlist {
			return &filters[i]
		}
	}
	return nil
}

// Current returns the level whose lists are exactly those enabled in AdGuard Home among the lists of
// the file, or "" when the state matches no level (lists changed by hand). Lists that the file does
// not mention are ignored.
func (l *Levels) Current(filters []FilterState) string {
	if l == nil {
		return ""
	}
	for _, k := range LevelKeys {
		lv := l.level(k)
		if lv == nil {
			continue
		}
		want := map[string]bool{}
		for _, id := range lv.Lists {
			want[id] = true
		}
		match := true
		for id, def := range l.Lists {
			f := find(filters, def)
			if (f != nil && f.Enabled) != want[id] {
				match = false
				break
			}
		}
		if match {
			return k
		}
	}
	return ""
}

// Action is one change to apply to AdGuard Home to reach a level.
type Action struct {
	Add       bool // add the list (enabled); otherwise change its enabled state
	URL       string
	Name      string
	Allowlist bool
	Enabled   bool
}

// Plan returns the changes that make the enabled lists of the file those of the level.
func (l *Levels) Plan(key string, filters []FilterState) ([]Action, error) {
	lv := l.level(key)
	if lv == nil {
		return nil, fmt.Errorf("niveau %q inconnu", key)
	}
	want := map[string]bool{}
	for _, id := range lv.Lists {
		want[id] = true
	}
	ids := make([]string, 0, len(l.Lists))
	for id := range l.Lists {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	var out []Action
	for _, id := range ids {
		def := l.Lists[id]
		f := find(filters, def)
		switch {
		case f == nil && want[id]:
			out = append(out, Action{Add: true, URL: def.URL, Name: def.Name, Allowlist: def.Allowlist, Enabled: true})
		case f != nil && f.Enabled != want[id]:
			out = append(out, Action{URL: def.URL, Name: f.Name, Allowlist: def.Allowlist, Enabled: want[id]})
		}
	}
	return out, nil
}
