package authmatrix

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Verdicts for one replayed request.
const (
	Allowed = "allowed"
	Denied  = "denied"
	Differs = "differs" // 2xx but unlike the owner's response: needs a human look
	Error   = "error"
	Skipped = "skipped"
)

// Observation is the part of a response the classifier looks at.
type Observation struct {
	Status   int
	Location string
	Body     []byte
}

// Observe parses a raw HTTP response.
func Observe(raw []byte) Observation {
	head, body, _ := bytes.Cut(raw, []byte("\r\n\r\n"))
	lines := strings.Split(string(head), "\r\n")
	var o Observation
	if f := strings.Fields(lines[0]); len(f) >= 2 {
		o.Status, _ = strconv.Atoi(f[1])
	}
	for _, l := range lines[1:] {
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(strings.TrimSpace(k), "Location") {
			o.Location = strings.TrimSpace(v)
		}
	}
	o.Body = body
	return o
}

var (
	loginRedirect = regexp.MustCompile(`(?i)(log-?in|sign-?in|auth|sso|session)`)
	passwordField = regexp.MustCompile(`(?i)<input[^>]+type\s*=\s*["']?password`)
	wordRe        = regexp.MustCompile(`[A-Za-z0-9_]{2,}`)
)

// Similarity is the Jaccard index of the two bodies' word sets (1 = same words).
func Similarity(a, b []byte) float64 {
	wa, wb := words(a), words(b)
	if len(wa) == 0 && len(wb) == 0 {
		return 1
	}
	inter := 0
	for w := range wa {
		if wb[w] {
			inter++
		}
	}
	return float64(inter) / float64(len(wa)+len(wb)-inter)
}

func words(b []byte) map[string]bool {
	m := map[string]bool{}
	for _, w := range wordRe.FindAll(b, -1) {
		m[strings.ToLower(string(w))] = true
	}
	return m
}

// Classify decides whether a replayed response granted access, comparing it
// with the owner's replay (baseline). loginPath is the site's login page path.
func Classify(o, baseline Observation, loginPath string) (verdict, reason string) {
	switch {
	case o.Status == 0:
		return Error, "no response"
	case o.Status == 401 || o.Status == 403:
		return Denied, strconv.Itoa(o.Status)
	case o.Status >= 300 && o.Status < 400:
		if loginRedirect.MatchString(o.Location) || (loginPath != "" && strings.Contains(o.Location, loginPath)) {
			return Denied, "redirect to login"
		}
		if baseline.Status == o.Status && baseline.Location == o.Location {
			return Allowed, "same redirect as owner"
		}
		return Differs, fmt.Sprintf("redirect to %s", o.Location)
	case o.Status == 404 || o.Status == 410:
		if baseline.Status == o.Status {
			return Differs, "owner also gets " + strconv.Itoa(o.Status)
		}
		return Denied, strconv.Itoa(o.Status)
	case o.Status >= 500:
		return Error, strconv.Itoa(o.Status)
	case o.Status >= 400:
		return Denied, strconv.Itoa(o.Status)
	}
	// 2xx
	if passwordField.Match(o.Body) && !passwordField.Match(baseline.Body) {
		return Denied, "login page"
	}
	if baseline.Status < 200 || baseline.Status >= 300 {
		return Differs, fmt.Sprintf("owner got %d", baseline.Status)
	}
	sim := Similarity(o.Body, baseline.Body)
	if sim >= 0.5 {
		return Allowed, fmt.Sprintf("%d, %.0f%% like owner", o.Status, sim*100)
	}
	return Differs, fmt.Sprintf("%d, only %.0f%% like owner", o.Status, sim*100)
}
