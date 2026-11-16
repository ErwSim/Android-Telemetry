package tracking

import (
	"errors"
	"regexp"
	"sort"
	"strings"
)

// Overrides are written in a block delimited by these comment lines among the AdGuard Home user rules.
// Rules outside the block (entered by hand in AdGuard) are never touched.
const (
	BlockBegin = "! watchpost:begin — règles gérées par la console Watchpost (vue « pistage ») : ne pas modifier à la main"
	BlockEnd   = "! watchpost:end"
)

// Override actions.
const (
	ActionBlock   = "block"
	ActionAllow   = "allow"
	ActionDefault = "default"
)

// ErrCorruptBlock is returned when the markers of the managed block are inconsistent: Watchpost then
// refuses to rewrite the rules rather than risk deleting rules of the owner.
var ErrCorruptBlock = errors.New("bloc Watchpost incohérent dans les règles personnalisées d'AdGuard Home (repères watchpost:begin / watchpost:end)")

var managedRuleRe = regexp.MustCompile(`^(@@)?\|\|([a-z0-9_.-]+)\^\$important$`)

func isBegin(l string) bool { return strings.HasPrefix(strings.TrimSpace(l), "! watchpost:begin") }
func isEnd(l string) bool   { return strings.TrimSpace(l) == BlockEnd }

// findBlock returns the indexes of the begin and end markers (-1, -1 when there is no block).
func findBlock(rules []string) (int, int, error) {
	begin, end := -1, -1
	for i, l := range rules {
		switch {
		case isBegin(l):
			if begin >= 0 {
				return 0, 0, ErrCorruptBlock
			}
			begin = i
		case isEnd(l):
			if end >= 0 || begin < 0 {
				return 0, 0, ErrCorruptBlock
			}
			end = i
		}
	}
	if (begin < 0) != (end < 0) {
		return 0, 0, ErrCorruptBlock
	}
	return begin, end, nil
}

// ParseOverrides returns the overrides of the managed block: domain -> "block" or "allow".
func ParseOverrides(rules []string) (map[string]string, error) {
	begin, end, err := findBlock(rules)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	if begin < 0 {
		return out, nil
	}
	for _, l := range rules[begin+1 : end] {
		m := managedRuleRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil || !ValidDomain(m[2]) {
			continue
		}
		if m[1] == "@@" {
			out[m[2]] = ActionAllow
		} else {
			out[m[2]] = ActionBlock
		}
	}
	return out, nil
}

// RuleFor returns the AdGuard rule of an override. $important makes it win over the filter lists:
// "||d^$important" blocks d and its subdomains, "@@||d^$important" lets them through.
func RuleFor(domain, action string) string {
	if action == ActionAllow {
		return "@@||" + domain + "^$important"
	}
	return "||" + domain + "^$important"
}

// ApplyOverride returns the user rules with the override of domain set (block, allow) or removed
// (default), and whether they changed. The block is rewritten sorted; it is appended at the end when
// absent and removed when empty. A line found between the markers that is not a rule written by Watchpost
// (a rule or a comment added there by hand in AdGuard Home) is never deleted: it is moved right after
// the block. The domain must already be validated (ValidDomain).
func ApplyOverride(rules []string, domain, action string) ([]string, bool, error) {
	if !ValidDomain(domain) {
		return nil, false, errors.New("nom de domaine invalide")
	}
	cur, err := ParseOverrides(rules)
	if err != nil {
		return nil, false, err
	}
	begin, end, _ := findBlock(rules)
	next := map[string]string{}
	for d, a := range cur {
		next[d] = a
	}
	switch action {
	case ActionBlock, ActionAllow:
		next[domain] = action
	case ActionDefault:
		delete(next, domain)
	default:
		return nil, false, errors.New("action inconnue")
	}
	domains := make([]string, 0, len(next))
	for d := range next {
		domains = append(domains, d)
	}
	sort.Strings(domains)
	var block []string
	if len(domains) > 0 {
		block = append(block, BlockBegin)
		for _, d := range domains {
			block = append(block, RuleFor(d, next[d]))
		}
		block = append(block, BlockEnd)
	}
	var out []string
	if begin < 0 {
		out = append(append(out, rules...), block...)
	} else {
		out = append(out, rules[:begin]...)
		out = append(out, block...)
		for _, l := range rules[begin+1 : end] {
			t := strings.TrimSpace(l)
			if m := managedRuleRe.FindStringSubmatch(t); t == "" || (m != nil && ValidDomain(m[2])) {
				continue
			}
			out = append(out, l) // not ours: kept, outside the block
		}
		out = append(out, rules[end+1:]...)
	}
	return out, !equalRules(out, rules), nil
}

func equalRules(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
