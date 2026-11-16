// Package tracking implements the "tracking" view of contract §9: classification of domains by
// publisher, validation of domain names, the essential domains guard, the rules block managed by
// Watchpost among the AdGuard Home user rules, the blocking levels file, and the aggregation of the view.
package tracking

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"
)

//go:embed publishers.txt
var publishersFile string

// Other is the publisher of a domain that matches no suffix.
const Other = "other"

// Publisher is one publisher of the classification file.
type Publisher struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

// Classifier attaches domains to publishers by suffix.
type Classifier struct {
	pubs   []Publisher
	names  map[string]string
	suffix map[string]string // domain suffix -> publisher key
}

var (
	headerRe = regexp.MustCompile(`^\[([a-z0-9_]{1,32})\]\s+(\S.{0,63})$`)
	labelRe  = regexp.MustCompile(`^[a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?$`)
)

// ParsePublishers reads a classification file (format described at the top of publishers.txt).
func ParsePublishers(text string) (*Classifier, error) {
	c := &Classifier{names: map[string]string{}, suffix: map[string]string{}}
	cur := ""
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := headerRe.FindStringSubmatch(line); m != nil {
			if _, dup := c.names[m[1]]; dup {
				return nil, fmt.Errorf("line %d: publisher %q defined twice", i+1, m[1])
			}
			cur = m[1]
			c.names[cur] = strings.TrimSpace(m[2])
			c.pubs = append(c.pubs, Publisher{Key: cur, Name: c.names[cur]})
			continue
		}
		if cur == "" {
			return nil, fmt.Errorf("line %d: suffix before any publisher", i+1)
		}
		if cur == Other {
			return nil, fmt.Errorf("line %d: publisher %q takes no suffix", i+1, Other)
		}
		if !ValidDomain(line) {
			return nil, fmt.Errorf("line %d: invalid suffix %q", i+1, line)
		}
		if prev, dup := c.suffix[line]; dup {
			return nil, fmt.Errorf("line %d: %q already attached to %q", i+1, line, prev)
		}
		c.suffix[line] = cur
	}
	if _, ok := c.names[Other]; !ok {
		return nil, fmt.Errorf("publisher %q missing", Other)
	}
	return c, nil
}

var defaultClassifier = func() *Classifier {
	c, err := ParsePublishers(publishersFile)
	if err != nil {
		panic("publishers.txt: " + err.Error())
	}
	return c
}()

// Default returns the classifier of the embedded publishers.txt.
func Default() *Classifier { return defaultClassifier }

// Publishers returns the publishers in display order.
func (c *Classifier) Publishers() []Publisher { return c.pubs }

// Valid reports whether key is a publisher key.
func (c *Classifier) Valid(key string) bool { _, ok := c.names[key]; return ok }

// Name returns the display name of a publisher.
func (c *Classifier) Name(key string) string { return c.names[key] }

// Classify returns the publisher of a domain: the longest listed suffix, on label boundaries.
func (c *Classifier) Classify(domain string) string {
	d := Normalize(domain)
	for d != "" {
		if p, ok := c.suffix[d]; ok {
			return p
		}
		i := strings.IndexByte(d, '.')
		if i < 0 {
			break
		}
		d = d[i+1:]
	}
	return Other
}

// Normalize lower-cases a domain name and removes a trailing dot.
func Normalize(d string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
}

// ValidDomain is the strict check of a domain name that ends up in an AdGuard rule: lower-case labels of
// [a-z0-9_-] (internationalized names in their xn-- form), 1 to 63 characters, no leading or trailing
// hyphen, at least two labels, 253 characters at most, and a top-level label that is not numeric (an IP
// address is not a domain). Nothing else can pass, so no rule syntax can be injected.
func ValidDomain(d string) bool {
	if len(d) == 0 || len(d) > 253 {
		return false
	}
	labels := strings.Split(d, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return false
		}
	}
	tld := labels[len(labels)-1]
	return strings.Trim(tld, "0123456789") != ""
}
