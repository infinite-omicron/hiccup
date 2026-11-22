package plextrac

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Repository is a WriteupsDB repository.
type Repository struct {
	ID      string `json:"repositoryId"`
	Name    string `json:"name"`
	Type    string `json:"repositoryType,omitempty"`
	Count   int    `json:"writeupsCount"`
	Deleted bool   `json:"isDeleted,omitempty"`
}

// Writeup is a WriteupsDB entry, with its rich-text fields as PlexTrac stores
// them (HTML). Text converts them for display.
type Writeup struct {
	ID              string            `json:"id"`
	DocID           any               `json:"doc_id,omitempty"`
	Title           string            `json:"title"`
	Severity        string            `json:"severity,omitempty"`
	RepositoryID    string            `json:"repositoryId,omitempty"`
	Repository      string            `json:"repository,omitempty"` // filled in from the repository list
	Description     string            `json:"description,omitempty"`
	Recommendations string            `json:"recommendations,omitempty"`
	References      string            `json:"references,omitempty"`
	Tags            []string          `json:"tags,omitempty"`
	Fields          map[string]string `json:"fields,omitempty"` // custom fields: label -> value
	CVE             []string          `json:"cve,omitempty"`
	CWE             []string          `json:"cwe,omitempty"`
	Source          string            `json:"source,omitempty"`
}

// rawWriteup is the shape of /template/list items.
type rawWriteup struct {
	ID              string          `json:"id"`
	DocID           any             `json:"doc_id"`
	Title           string          `json:"title"`
	Severity        string          `json:"severity"`
	RepositoryID    string          `json:"repositoryId"`
	Description     string          `json:"description"`
	Recommendations string          `json:"recommendations"`
	References      string          `json:"references"`
	Tags            json.RawMessage `json:"tags"`
	Fields          map[string]struct {
		Label string `json:"label"`
		Value any    `json:"value"`
	} `json:"fields"`
	CommonIdentifiers struct {
		CVE []struct {
			Name string `json:"name"`
		} `json:"CVE"`
		CWE []struct {
			Name string `json:"name"`
		} `json:"CWE"`
	} `json:"common_identifiers"`
	Source  string `json:"source"`
	Deleted bool   `json:"isDeleted"`
}

func (r rawWriteup) writeup() Writeup {
	w := Writeup{ID: r.ID, DocID: r.DocID, Title: strings.TrimSpace(r.Title), Severity: r.Severity, RepositoryID: r.RepositoryID,
		Description: r.Description, Recommendations: r.Recommendations, References: r.References, Source: r.Source}
	if w.ID == "" && r.DocID != nil {
		w.ID = fmt.Sprint(r.DocID)
	}
	// tags are usually ["a","b"], sometimes a comma-separated string.
	var tags []string
	if json.Unmarshal(r.Tags, &tags) != nil {
		var s string
		if json.Unmarshal(r.Tags, &s) == nil && s != "" {
			for _, t := range strings.Split(s, ",") {
				tags = append(tags, strings.TrimSpace(t))
			}
		}
	}
	w.Tags = tags
	for key, f := range r.Fields {
		if key == "scores" || f.Value == nil {
			continue
		}
		label := f.Label
		if label == "" {
			label = key
		}
		if w.Fields == nil {
			w.Fields = map[string]string{}
		}
		if s, ok := f.Value.(string); ok {
			w.Fields[label] = s
		} else if b, err := json.Marshal(f.Value); err == nil {
			w.Fields[label] = string(b)
		}
	}
	for _, c := range r.CommonIdentifiers.CVE {
		w.CVE = append(w.CVE, c.Name)
	}
	for _, c := range r.CommonIdentifiers.CWE {
		w.CWE = append(w.CWE, c.Name)
	}
	return w
}

// Repositories lists the WriteupsDB repositories the account can read.
func (c *Client) Repositories(ctx context.Context) ([]Repository, error) {
	var out struct {
		Data []Repository `json:"data"`
	}
	if err := c.do(ctx, "POST", pathRepositories, map[string]any{}, &out); err != nil {
		return nil, err
	}
	repos := out.Data[:0]
	for _, r := range out.Data {
		if !r.Deleted {
			repos = append(repos, r)
		}
	}
	return repos, nil
}

// Writeups lists every write-up the account can read (deleted ones excluded).
func (c *Client) Writeups(ctx context.Context) ([]Writeup, error) {
	var raw []rawWriteup
	if err := c.do(ctx, "GET", pathWriteups, nil, &raw); err != nil {
		return nil, err
	}
	out := make([]Writeup, 0, len(raw))
	for _, r := range raw {
		if !r.Deleted {
			out = append(out, r.writeup())
		}
	}
	return out, nil
}

// Writeup fetches one write-up by ID.
func (c *Client) Writeup(ctx context.Context, id string) (*Writeup, error) {
	var r rawWriteup
	if err := c.do(ctx, "GET", pathWriteup+id, nil, &r); err != nil {
		return nil, err
	}
	w := r.writeup()
	return &w, nil
}

// Library is the local copy of the write-ups, so searching and matching work
// offline (sessions only last 15 minutes and sign-in needs an MFA code).
type Library struct {
	URL          string       `json:"url"`
	SyncedAt     time.Time    `json:"synced_at"`
	Repositories []Repository `json:"repositories"`
	Writeups     []Writeup    `json:"writeups"`
}

func libraryPath() string { return filepath.Join(dir(), "writeups.json") }

// Sync downloads the repositories and write-ups. only limits them to
// repositories named or with an ID in the list (case-insensitive).
func (c *Client) Sync(ctx context.Context, only []string) (*Library, error) {
	repos, err := c.Repositories(ctx)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, r := range repos {
		if len(only) == 0 || matchesAny(r, only) {
			keep[r.ID] = true
		}
	}
	if len(only) > 0 && len(keep) == 0 {
		var names []string
		for _, r := range repos {
			names = append(names, r.Name)
		}
		return nil, fmt.Errorf("plextrac: no repository matches %v (available: %s)", only, strings.Join(names, ", "))
	}
	all, err := c.Writeups(ctx)
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	var kept []Repository
	for _, r := range repos {
		if keep[r.ID] {
			names[r.ID] = r.Name
			kept = append(kept, r)
		}
	}
	lib := &Library{URL: c.URL, SyncedAt: time.Now().UTC(), Repositories: kept}
	for _, w := range all {
		if len(only) > 0 && !keep[w.RepositoryID] {
			continue
		}
		w.Repository = names[w.RepositoryID]
		lib.Writeups = append(lib.Writeups, w)
	}
	sort.Slice(lib.Writeups, func(i, j int) bool {
		return strings.ToLower(lib.Writeups[i].Title) < strings.ToLower(lib.Writeups[j].Title)
	})
	return lib, nil
}

func matchesAny(r Repository, only []string) bool {
	for _, o := range only {
		if strings.EqualFold(o, r.ID) || strings.EqualFold(o, r.Name) {
			return true
		}
	}
	return false
}

func (l *Library) Save() error {
	if err := os.MkdirAll(dir(), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(l, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(libraryPath(), b, 0o600)
}

// LoadLibrary returns the write-ups from the last sync.
func LoadLibrary() (*Library, error) {
	b, err := os.ReadFile(libraryPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, errors.New("plextrac: no write-ups yet (hiccup plextrac sync)")
	} else if err != nil {
		return nil, err
	}
	var l Library
	return &l, json.Unmarshal(b, &l)
}

// Find returns the write-up with this ID, or else exactly this title (case-insensitive).
func (l *Library) Find(ref string) *Writeup {
	for i := range l.Writeups {
		if l.Writeups[i].ID == ref || fmt.Sprint(l.Writeups[i].DocID) == ref {
			return &l.Writeups[i]
		}
	}
	for i := range l.Writeups {
		if strings.EqualFold(l.Writeups[i].Title, strings.TrimSpace(ref)) {
			return &l.Writeups[i]
		}
	}
	return nil
}

// Search returns write-ups whose title, tags or text contain every term.
func (l *Library) Search(terms []string, repository string) []Writeup {
	var out []Writeup
	for _, w := range l.Writeups {
		if repository != "" && !strings.EqualFold(repository, w.Repository) && !strings.EqualFold(repository, w.RepositoryID) {
			continue
		}
		hay := strings.ToLower(w.Title + " " + strings.Join(w.Tags, " ") + " " + Text(w.Description))
		ok := true
		for _, t := range terms {
			if !strings.Contains(hay, strings.ToLower(t)) {
				ok = false
				break
			}
		}
		if ok {
			out = append(out, w)
		}
	}
	return out
}
