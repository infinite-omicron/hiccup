package authmatrix

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

// Account is one row of the matrix.
type Account struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	Level     int    `json:"level"`
	Anonymous bool   `json:"anonymous,omitempty"`
}

// Overrides pin expectations: action name → role or account name → "allow"/"deny".
// "*" as the action applies to every action.
type Overrides map[string]map[string]string

func overridesPath(site string) string { return filepath.Join(Dir(site), "expectations.json") }

func LoadOverrides(site string) (Overrides, error) {
	var o Overrides
	err := readJSON(overridesPath(site), &o)
	if errors.Is(err, fs.ErrNotExist) {
		return Overrides{}, nil
	}
	return o, err
}

func (o Overrides) lookup(action string, a Account) (string, bool) {
	for _, act := range []string{action, "*"} {
		m := o[act]
		for _, k := range []string{a.Name, a.Role} {
			if v, ok := m[k]; ok {
				v = strings.ToLower(v)
				if v != "allow" && v != "deny" {
					continue
				}
				return v, true
			}
		}
	}
	return "", false
}

// Expect decides whether account a should be able to make request r that
// recorder made during action. known maps a request Key to the lowest level of
// any account whose own recording contains it.
//
//   - the recorder itself: allow
//   - an override in expectations.json wins
//   - a reference to the recorder's own object (/documents/42): only higher levels
//   - otherwise: allow if a's level is at least the recorder's, or if some
//     account at a's level or below recorded the same request itself
func Expect(a, recorder Account, action string, r RecordedRequest, known map[string]int, o Overrides) (allow bool, why string) {
	if a.Name == recorder.Name {
		return true, "owner"
	}
	if v, ok := o.lookup(action, a); ok {
		return v == "allow", "expectations.json"
	}
	if r.ObjectRef {
		if a.Level > recorder.Level {
			return true, fmt.Sprintf("higher level than %s", recorder.Name)
		}
		return false, fmt.Sprintf("%s's object", recorder.Name)
	}
	if a.Level >= recorder.Level {
		return true, fmt.Sprintf("level %d ≥ %d", a.Level, recorder.Level)
	}
	if lvl, ok := known[r.Key()]; ok && a.Level >= lvl {
		return true, "seen in a lower-level recording"
	}
	return false, fmt.Sprintf("level %d < %d", a.Level, recorder.Level)
}

// Finding names the access-control flaw when access was granted but not expected.
func Finding(a, recorder Account, expectAllow bool, verdict string) string {
	switch {
	case expectAllow || (verdict != Allowed && verdict != Differs):
		return ""
	case verdict == Differs:
		return "review"
	case a.Anonymous:
		return "forceful-browsing"
	case a.Level < recorder.Level:
		return "vertical"
	default:
		return "horizontal"
	}
}
