package plextrac

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Mapping maps finding names (Burp issue names, auth-matrix codes or labels)
// to write-up IDs or titles. It lives in its own file, so each company keeps
// and shares its mapping outside hiccup's config.
type Mapping map[string]string

// MappingPath resolves the config's "map" value: absolute, ~/..., or relative
// to ~/.hiccup/plextrac/. Empty means mapping.json.
func MappingPath(name string) string {
	if name == "" {
		name = "mapping.json"
	}
	if strings.HasPrefix(name, "~/") || name == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(name, "~"))
		}
	}
	if filepath.IsAbs(name) {
		return name
	}
	return filepath.Join(dir(), name)
}

// LoadMapping reads a mapping file; a missing file is an empty mapping.
func LoadMapping(path string) (Mapping, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return Mapping{}, nil
	} else if err != nil {
		return nil, err
	}
	m := Mapping{}
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

func (m Mapping) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o600)
}

// lookup finds the mapping for a finding, ignoring case and spacing.
func (m Mapping) lookup(names ...string) (string, bool) {
	for _, n := range names {
		if v, ok := m[n]; ok {
			return v, true
		}
	}
	for _, n := range names {
		for k, v := range m {
			if normalize(k) == normalize(n) {
				return v, true
			}
		}
	}
	return "", false
}

// Finding is something to find a write-up for.
type Finding struct {
	Name    string   `json:"name"`              // e.g. "Strict transport security not enforced", "Potential Vertical Privilege Escalation"
	Aliases []string `json:"aliases,omitempty"` // other keys a mapping may use, e.g. the matrix code "vertical"
	Source  string   `json:"source,omitempty"`  // burp, matrix or name
	Count   int      `json:"count,omitempty"`   // instances
}

// Suggestion is a candidate write-up with its score (0-1).
type Suggestion struct {
	ID    string  `json:"id"`
	Title string  `json:"title"`
	Score float64 `json:"score"`
}

// Match is the write-up chosen for a finding, and how.
type Match struct {
	Finding     Finding      `json:"finding"`
	How         string       `json:"how"` // mapped, exact, fuzzy or unmatched
	Writeup     *Writeup     `json:"writeup,omitempty"`
	Score       float64      `json:"score,omitempty"`
	Suggestions []Suggestion `json:"suggestions,omitempty"`
	Problem     string       `json:"problem,omitempty"` // e.g. a mapping to a write-up that no longer exists
}

// Threshold is the lowest fuzzy score accepted as a match.
const Threshold = 0.5

// MatchAll matches each finding: the mapping first, then an exact title, then
// the best fuzzy title (with the top suggestions kept for review).
func (l *Library) MatchAll(findings []Finding, m Mapping) []Match {
	out := make([]Match, 0, len(findings))
	for _, f := range findings {
		out = append(out, l.match(f, m))
	}
	return out
}

func (l *Library) match(f Finding, m Mapping) Match {
	r := Match{Finding: f}
	if ref, ok := m.lookup(append([]string{f.Name}, f.Aliases...)...); ok {
		if w := l.Find(ref); w != nil {
			r.How, r.Writeup, r.Score = "mapped", w, 1
			return r
		}
		r.Problem = "mapped to " + ref + ", which isn't in the synced write-ups"
	}
	for _, n := range append([]string{f.Name}, f.Aliases...) {
		for i := range l.Writeups {
			if normalize(l.Writeups[i].Title) == normalize(n) {
				r.How, r.Writeup, r.Score = "exact", &l.Writeups[i], 1
				return r
			}
		}
	}
	type scored struct {
		i int
		s float64
	}
	var all []scored
	for i := range l.Writeups {
		best := 0.0
		for _, n := range append([]string{f.Name}, f.Aliases...) {
			if s := similarity(n, l.Writeups[i].Title); s > best {
				best = s
			}
		}
		if best > 0 {
			all = append(all, scored{i, best})
		}
	}
	sort.SliceStable(all, func(a, b int) bool { return all[a].s > all[b].s })
	for _, s := range all[:min(3, len(all))] {
		w := l.Writeups[s.i]
		r.Suggestions = append(r.Suggestions, Suggestion{ID: w.ID, Title: w.Title, Score: round2(s.s)})
	}
	if len(all) > 0 && all[0].s >= Threshold {
		r.How, r.Writeup, r.Score = "fuzzy", &l.Writeups[all[0].i], round2(all[0].s)
		return r
	}
	r.How = "unmatched"
	return r
}

func round2(f float64) float64 { return float64(int(f*100+0.5)) / 100 }

// stop words carry no meaning for matching finding titles.
var stop = map[string]bool{"a": true, "an": true, "the": true, "of": true, "in": true, "on": true, "to": true, "for": true,
	"and": true, "or": true, "is": true, "not": true, "with": true, "without": true, "via": true, "potential": true,
	"detected": true, "found": true, "set": true, "issue": true, "vulnerability": true,
	// generic descriptions that don't say what the finding is about
	"weakness": true, "weaknesses": true, "misconfiguration": true, "misconfigured": true, "missing": true,
	"allows": true, "supported": true, "enforced": true, "disclosed": true, "revealed": true, "response": true}

// synonyms fold common spellings of the same concept together.
var synonyms = map[string]string{"hsts": "strict-transport-security", "https": "tls", "ssl": "tls", "csp": "content-security-policy",
	"xss": "cross-site-scripting", "csrf": "cross-site-request-forgery", "idor": "insecure-direct-object-reference",
	"ciphers": "cipher", "cookies": "cookie", "headers": "header", "certificates": "certificate"}

var phrases = []struct{ from, to string }{
	{"strict transport security", "strict-transport-security"}, {"content security policy", "content-security-policy"},
	{"cross site scripting", "cross-site-scripting"}, {"cross site request forgery", "cross-site-request-forgery"},
	{"privilege escalation", "privilege-escalation"}, {"access control", "access-control"},
	{"insecure direct object reference", "insecure-direct-object-reference"},
}

func normalize(s string) string { return strings.Join(tokens(s), " ") }

func tokens(s string) []string {
	s = strings.ToLower(s)
	s = strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' {
			return r
		}
		return ' '
	}, s)
	s = " " + strings.Join(strings.Fields(s), " ") + " "
	for _, p := range phrases {
		s = strings.ReplaceAll(s, " "+p.from+" ", " "+p.to+" ")
	}
	var out []string
	for _, t := range strings.Fields(s) {
		t = strings.Trim(t, ".")
		if t == "" || stop[t] {
			continue
		}
		if v, ok := synonyms[t]; ok {
			t = v
		}
		out = append(out, t)
	}
	return out
}

// similarity is the token overlap (Jaccard) of two titles, raised when one
// title's tokens are all contained in the other's.
func similarity(a, b string) float64 {
	ta, tb := set(tokens(a)), set(tokens(b))
	if len(ta) == 0 || len(tb) == 0 {
		return 0
	}
	inter := 0
	for t := range ta {
		if tb[t] {
			inter++
		}
	}
	union := len(ta) + len(tb) - inter
	j := float64(inter) / float64(union)
	if inter == min(len(ta), len(tb)) && inter > 0 {
		j = max(j, 0.6+0.4*j)
	}
	return j
}

func set(ts []string) map[string]bool {
	m := map[string]bool{}
	for _, t := range ts {
		m[t] = true
	}
	return m
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
