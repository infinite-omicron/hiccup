package authmatrix

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/infinite-omicron/hiccup/internal/config"
	"github.com/infinite-omicron/hiccup/internal/proxy"
)

// Mark starts an action: proxy history items with id > FromID belong to it,
// until the next mark.
type Mark struct {
	Action string `json:"action"`
	FromID int    `json:"from_id"`
}

type RecordedRequest struct {
	ID        int    `json:"id"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Template  string `json:"template"`
	ObjectRef bool   `json:"object_ref"`
	Status    *int   `json:"status,omitempty"`
}

// Key identifies a request shape across accounts: method plus path template.
func (r RecordedRequest) Key() string { return r.Method + " " + r.Template }

type Action struct {
	Name     string            `json:"name"`
	Requests []RecordedRequest `json:"requests"`
}

type Recording struct {
	Site    string    `json:"site"`
	Account string    `json:"account"`
	Role    string    `json:"role"`
	Level   int       `json:"level"`
	Created time.Time `json:"created"`
	Actions []Action  `json:"actions"`
}

// State is an in-progress recording (manual mode, between start and stop).
// Each account has its own, so several can record at once (--parallel).
type State struct {
	Site    string `json:"site"`
	Account string `json:"account"`
	StartID int    `json:"start_id"`
	Marks   []Mark `json:"marks"`
	// ListenerPort limits the recording to requests from the account's own
	// browser (--parallel); 0 takes every request.
	ListenerPort int `json:"listener_port,omitempty"`
	path         string
}

func Dir(site string) string { return filepath.Join(config.Home(), "sites", site) }

func statePath(site, account string) string {
	return filepath.Join(Dir(site), "recording-state-"+account+".json")
}

// legacyStatePath is the single recording state of hiccup before --parallel.
func legacyStatePath(site string) string { return filepath.Join(Dir(site), "recording-state.json") }

func recordingPath(site, account string) string {
	return filepath.Join(Dir(site), "recordings", account+".json")
}

func writeJSON(p string, v any) error {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, b, 0o600)
}

func readJSON(p string, v any) error {
	b, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func SaveState(s *State) error {
	if s.path == "" {
		s.path = statePath(s.Site, s.Account)
	}
	return writeJSON(s.path, s)
}

// States returns every recording in progress for the site.
func States(site string) ([]*State, error) {
	files, err := filepath.Glob(filepath.Join(Dir(site), "recording-state-*.json"))
	if err != nil {
		return nil, err
	}
	if _, err := os.Stat(legacyStatePath(site)); err == nil {
		files = append(files, legacyStatePath(site))
	}
	var out []*State
	for _, f := range files {
		var s State
		if err := readJSON(f, &s); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		s.path = f
		out = append(out, &s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Account < out[j].Account })
	return out, nil
}

// LoadState returns the account's recording in progress, or the only one when
// account is "".
func LoadState(site, account string) (*State, error) {
	states, err := States(site)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, s := range states {
		if s.Account == account {
			return s, nil
		}
		names = append(names, s.Account)
	}
	switch {
	case account == "" && len(states) == 1:
		return states[0], nil
	case account == "" && len(states) > 1:
		return nil, fmt.Errorf("recordings in progress for %s: pass --as to pick one", strings.Join(names, ", "))
	case account != "":
		return nil, fmt.Errorf("no recording in progress for %s (hiccup matrix record --as %s --manual)", account, account)
	}
	return nil, fmt.Errorf("no recording in progress for %s (hiccup matrix record --as <account> --manual)", site)
}

func ClearState(s *State) error {
	err := os.Remove(s.path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func SaveRecording(r *Recording) error { return writeJSON(recordingPath(r.Site, r.Account), r) }

// LoadRecordings returns every saved recording for a site, highest level first.
func LoadRecordings(site string) ([]*Recording, error) {
	files, err := filepath.Glob(filepath.Join(Dir(site), "recordings", "*.json"))
	if err != nil {
		return nil, err
	}
	var out []*Recording
	for _, f := range files {
		var r Recording
		if err := readJSON(f, &r); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		out = append(out, &r)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Level > out[j].Level })
	return out, nil
}

var (
	staticExt  = map[string]bool{".js": true, ".mjs": true, ".css": true, ".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true, ".ico": true, ".webp": true, ".woff": true, ".woff2": true, ".ttf": true, ".eot": true, ".map": true}
	staticMIME = []string{"SCRIPT", "CSS", "IMAGE", "FONT", "SOUND", "VIDEO"}
	// Replaying a logout would kill the session it is replayed with.
	DefaultExclude = regexp.MustCompile(`(?i)(log-?out|sign-?out|log-?off|/favicon\.ico)`)
)

// Filter decides which history items belong in a recording.
type Filter struct {
	Hosts   []string
	Exclude []*regexp.Regexp
}

func (f Filter) keep(s proxy.Summary) bool {
	u, err := url.Parse(s.URL)
	if err != nil {
		return false
	}
	inScope := len(f.Hosts) == 0
	for _, h := range f.Hosts {
		if strings.EqualFold(u.Hostname(), h) {
			inScope = true
		}
	}
	if !inScope || staticExt[strings.ToLower(path.Ext(u.Path))] {
		return false
	}
	for _, m := range staticMIME {
		if strings.HasPrefix(s.MIME, m) {
			return false
		}
	}
	for _, re := range f.Exclude {
		if re.MatchString(s.URL) {
			return false
		}
	}
	return true
}

// Build groups proxy history items into actions by marks, keeping in-scope,
// non-static requests and one request per method+template per action.
func Build(items []proxy.Summary, marks []Mark, f Filter) []Action {
	sort.Slice(marks, func(i, j int) bool { return marks[i].FromID < marks[j].FromID })
	sort.Slice(items, func(i, j int) bool { return items[i].ID < items[j].ID })
	var actions []Action
	index := map[string]int{}
	seen := map[string]bool{}
	for _, it := range items {
		mi := -1
		for i, m := range marks {
			if it.ID > m.FromID {
				mi = i
			}
		}
		if mi < 0 || !f.keep(it) {
			continue
		}
		name := marks[mi].Action
		tmpl, ref := Template(it.URL)
		r := RecordedRequest{ID: it.ID, Method: it.Method, URL: it.URL, Template: tmpl, ObjectRef: ref, Status: it.Status}
		if seen[name+"\x00"+r.Key()] {
			continue
		}
		seen[name+"\x00"+r.Key()] = true
		ai, ok := index[name]
		if !ok {
			ai = len(actions)
			index[name] = ai
			actions = append(actions, Action{Name: name})
		}
		actions[ai].Requests = append(actions[ai].Requests, r)
	}
	return actions
}
