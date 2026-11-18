package authmatrix

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/infinite-omicron/hiccup/internal/backend"
	"github.com/infinite-omicron/hiccup/internal/session"
)

// Cell is one account's result for one replayed request.
type Cell struct {
	Account     string `json:"account"`
	Expected    string `json:"expected"` // allow or deny
	Why         string `json:"why"`
	Verdict     string `json:"verdict"`
	Reason      string `json:"reason,omitempty"`
	Status      int    `json:"status,omitempty"`
	Finding     string `json:"finding,omitempty"` // vertical, horizontal, forceful-browsing, review
	RequestB64  string `json:"request_b64,omitempty"`
	ResponseB64 string `json:"response_b64,omitempty"`
}

type RequestResult struct {
	RecordedRequest
	Recorder string `json:"recorder"`
	Cells    []Cell `json:"cells"`
}

type ActionResult struct {
	Name     string          `json:"name"`
	Requests []RequestResult `json:"requests"`
}

type Matrix struct {
	Site      string         `json:"site"`
	Generated time.Time      `json:"generated"`
	Accounts  []Account      `json:"accounts"`
	Actions   []ActionResult `json:"actions"`
}

func matrixPath(site string) string { return filepath.Join(Dir(site), "matrix.json") }

func (m *Matrix) Save() error { return writeJSON(matrixPath(m.Site), m) }

func LoadMatrix(site string) (*Matrix, error) {
	var m Matrix
	if err := readJSON(matrixPath(site), &m); errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("no matrix for %s yet (hiccup matrix run %s)", site, site)
	} else if err != nil {
		return nil, err
	}
	return &m, nil
}

// Findings returns every cell with a finding other than "review" (or with it, when review is set).
func (m *Matrix) Findings(review bool) []FindingRef {
	var out []FindingRef
	for ai := range m.Actions {
		for ri := range m.Actions[ai].Requests {
			r := &m.Actions[ai].Requests[ri]
			for ci := range r.Cells {
				f := r.Cells[ci].Finding
				if f != "" && (review || f != "review") {
					out = append(out, FindingRef{Action: m.Actions[ai].Name, Request: r, Cell: &r.Cells[ci]})
				}
			}
		}
	}
	return out
}

type FindingRef struct {
	Action  string
	Request *RequestResult
	Cell    *Cell
}

// SafeMethods are replayed by default; others change state and need Unsafe.
var SafeMethods = []string{"GET", "HEAD", "OPTIONS"}

type RunOptions struct {
	Site        string
	Recordings  []*Recording
	Accounts    []Account
	Sessions    map[string]*session.Session // by account name
	StripHeader []string                    // session headers to remove before injecting
	LoginPath   string
	Overrides   Overrides
	Unsafe      bool
	Concurrency int
	Progress    func(done, total int)
}

// Run replays every recorded request as every account through b.
func Run(ctx context.Context, b backend.Backend, o RunOptions) (*Matrix, error) {
	byName := map[string]Account{}
	for _, a := range o.Accounts {
		byName[a.Name] = a
	}
	known := map[string]int{}
	for _, rec := range o.Recordings {
		for _, act := range rec.Actions {
			for _, r := range act.Requests {
				if lvl, ok := known[r.Key()]; !ok || rec.Level < lvl {
					known[r.Key()] = rec.Level
				}
			}
		}
	}

	m := &Matrix{Site: o.Site, Generated: time.Now().UTC(), Accounts: o.Accounts}
	type job struct{ ai, ri int }
	var jobs []job
	actionIdx := map[string]int{}
	// The same request recorded by several accounts is replayed once (from the
	// highest-level recording, which comes first), unless it references an
	// object: each account's own objects are worth testing separately.
	seen := map[string]bool{}
	for _, rec := range o.Recordings {
		recorder, ok := byName[rec.Account]
		if !ok {
			return nil, fmt.Errorf("recording by %q, which is not an account in the site config", rec.Account)
		}
		for _, act := range rec.Actions {
			ai, ok := actionIdx[act.Name]
			if !ok {
				ai = len(m.Actions)
				actionIdx[act.Name] = ai
				m.Actions = append(m.Actions, ActionResult{Name: act.Name})
			}
			for _, r := range act.Requests {
				if k := act.Name + "\x00" + r.Key(); !r.ObjectRef {
					if seen[k] {
						continue
					}
					seen[k] = true
				}
				rr := RequestResult{RecordedRequest: r, Recorder: recorder.Name}
				m.Actions[ai].Requests = append(m.Actions[ai].Requests, rr)
				jobs = append(jobs, job{ai, len(m.Actions[ai].Requests) - 1})
			}
		}
	}

	workers := max(1, o.Concurrency)
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	done := 0
	for _, j := range jobs {
		rr := &m.Actions[j.ai].Requests[j.ri]
		action := m.Actions[j.ai].Name
		wg.Add(1)
		sem <- struct{}{}
		go func() {
			defer func() { <-sem; wg.Done() }()
			err := replay(ctx, b, o, byName, known, action, rr)
			mu.Lock()
			defer mu.Unlock()
			if err != nil && firstErr == nil {
				firstErr = err
			}
			done++
			if o.Progress != nil {
				o.Progress(done, len(jobs))
			}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	return m, nil
}

func replay(ctx context.Context, b backend.Backend, o RunOptions, byName map[string]Account, known map[string]int, action string, rr *RequestResult) error {
	recorder := byName[rr.Recorder]
	cells := make([]Cell, len(o.Accounts))
	for i, a := range o.Accounts {
		allow, why := Expect(a, recorder, action, rr.RecordedRequest, known, o.Overrides)
		cells[i] = Cell{Account: a.Name, Expected: map[bool]string{true: "allow", false: "deny"}[allow], Why: why}
	}
	if !o.Unsafe && !slices.Contains(SafeMethods, strings.ToUpper(rr.Method)) {
		for i := range cells {
			cells[i].Verdict, cells[i].Reason = Skipped, "state-changing method (use --unsafe)"
		}
		rr.Cells = cells
		return nil
	}

	orig, err := b.HistoryItem(ctx, rr.ID)
	if err != nil {
		return fmt.Errorf("proxy history item %d (%s %s): %w", rr.ID, rr.Method, rr.URL, err)
	}
	u, err := url.Parse(rr.URL)
	if err != nil {
		return err
	}
	https := u.Scheme == "https"
	port := 0
	if p := u.Port(); p != "" {
		fmt.Sscan(p, &port)
	}
	reqs := make([]backend.Request, len(o.Accounts))
	for i, a := range o.Accounts {
		s := o.Sessions[a.Name]
		if s == nil {
			s = session.Anonymous(o.Site, a.Name)
		}
		raw := s.Apply(orig.Request(), u.Hostname(), o.StripHeader)
		reqs[i] = backend.Request{RawB64: base64.StdEncoding.EncodeToString(raw), Host: u.Hostname(), Port: port, HTTPS: &https}
	}
	exs, err := b.Send(ctx, reqs)
	if err != nil {
		return err
	}
	if len(exs) != len(reqs) {
		return fmt.Errorf("sent %d requests, got %d responses", len(reqs), len(exs))
	}
	var baseline Observation
	for i, a := range o.Accounts {
		if a.Name == recorder.Name {
			baseline = Observe(exs[i].Response())
		}
	}
	for i, a := range o.Accounts {
		obs := Observe(exs[i].Response())
		c := &cells[i]
		c.Status = obs.Status
		c.Verdict, c.Reason = Classify(obs, baseline, o.LoginPath)
		if a.Name == recorder.Name {
			c.Verdict, c.Reason = baselineVerdict(obs), "owner's own replay"
		}
		c.Finding = Finding(a, recorder, c.Expected == "allow", c.Verdict)
		c.RequestB64, c.ResponseB64 = exs[i].RequestB64, exs[i].ResponseB64
	}
	rr.Cells = cells
	return nil
}

// baselineVerdict reports whether the owner's own replay still works; if not,
// its session has probably expired and the row can't be trusted.
func baselineVerdict(o Observation) string {
	switch {
	case o.Status >= 200 && o.Status < 400 && !loginRedirect.MatchString(o.Location):
		return Allowed
	case o.Status == 0 || o.Status >= 500:
		return Error
	default:
		return Denied
	}
}
