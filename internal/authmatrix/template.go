// Package authmatrix records which requests each action makes, replays them as
// every account, and reports horizontal/vertical privilege escalation.
package authmatrix

import (
	"net/url"
	"path"
	"regexp"
	"slices"
	"sort"
	"strings"
)

var (
	uuidRe  = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	hexRe   = regexp.MustCompile(`^[0-9a-fA-F]{16,}$`)
	tokenRe = regexp.MustCompile(`^[A-Za-z0-9_-]{20,}$`)
	digitRe = regexp.MustCompile(`[0-9]`)
)

// idLike reports whether a path segment or query value looks like an object reference.
func idLike(s string) bool {
	if s == "" {
		return false
	}
	if strings.Trim(s, "0123456789") == "" {
		return true
	}
	return uuidRe.MatchString(s) || hexRe.MatchString(s) || (tokenRe.MatchString(s) && digitRe.MatchString(s))
}

// fileLike reports whether a segment names a file, e.g. "report.pdf".
func fileLike(s string) bool {
	ext := path.Ext(s)
	return len(ext) > 1 && len(ext) <= 6 && len(s) > len(ext)
}

func singular(s string) string {
	s = strings.ToLower(strings.Trim(s, "-_"))
	switch {
	case s == "":
		return "object"
	case strings.HasSuffix(s, "ies") && len(s) > 4:
		return s[:len(s)-3] + "y"
	case strings.HasSuffix(s, "s") && !strings.HasSuffix(s, "ss") && len(s) > 3:
		return s[:len(s)-1]
	}
	return s
}

// Template turns a URL into a path template, replacing object references
// with named placeholders: /documents/42 → /documents/${document_id},
// /upload/report.pdf → /upload/${upload_name}. objectRef reports whether any
// placeholder was introduced.
func Template(rawURL string) (tmpl string, objectRef bool) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL, false
	}
	segs := strings.Split(u.EscapedPath(), "/")
	prev := ""
	for i, s := range segs {
		if s == "" {
			continue
		}
		dec, _ := url.PathUnescape(s)
		switch {
		case idLike(dec):
			segs[i], objectRef = "${"+singular(prev)+"_id}", true
		case fileLike(dec) && i == len(segs)-1 && prev != "":
			segs[i], objectRef = "${"+singular(prev)+"_name}", true
		}
		prev = dec
	}
	tmpl = strings.Join(segs, "/")
	if tmpl == "" {
		tmpl = "/"
	}
	if q := u.Query(); len(q) > 0 {
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = k + "=${" + k + "}"
			if idLike(q.Get(k)) {
				objectRef = true
			}
		}
		tmpl += "?" + strings.Join(parts, "&")
	}
	return tmpl, objectRef
}

// ActionSeparator joins the levels of a menu path in action names.
const ActionSeparator = " -> "

// ActionName names an action after its menu path: "Content -> Scheduled content".
func ActionName(path []string) string { return strings.Join(path, ActionSeparator) }

// JoinPath appends a link's menu path to the path of the page it was found
// on, without repeating labels the two share: on the "Content" page, a
// link whose own path is ["Content", "Scheduled content"] (or just
// ["Scheduled content"]) becomes ["Content", "Scheduled content"].
func JoinPath(parent, child []string) []string {
	overlap := 0
	for k := min(len(parent), len(child)); k > 0; k-- {
		if slices.EqualFunc(parent[len(parent)-k:], child[:k], strings.EqualFold) {
			overlap = k
			break
		}
	}
	out := append(append([]string{}, parent...), child[overlap:]...)
	if len(out) == 0 {
		return child
	}
	return out
}
