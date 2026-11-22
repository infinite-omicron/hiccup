package plextrac

import (
	"html"
	"regexp"
	"strings"
)

var (
	reBreak  = regexp.MustCompile(`(?i)<br\s*/?>`)
	reBlock  = regexp.MustCompile(`(?i)</?(p|div|h[1-6]|ul|ol|table|tr|blockquote|pre)\b[^>]*>`)
	reItem   = regexp.MustCompile(`(?i)<li\b[^>]*>`)
	reCell   = regexp.MustCompile(`(?i)</t[dh]>`)
	reLink   = regexp.MustCompile(`(?is)<a\b[^>]*href\s*=\s*["']([^"']+)["'][^>]*>(.*?)</a>`)
	reBold   = regexp.MustCompile(`(?is)<(b|strong)\b[^>]*>(.*?)</(b|strong)>`)
	reCode   = regexp.MustCompile(`(?is)<code\b[^>]*>(.*?)</code>`)
	reTag    = regexp.MustCompile(`(?s)<[^>]+>`)
	reSpaces = regexp.MustCompile(`[ \t\f\v]+`)
	reBlank  = regexp.MustCompile(`\n\s*\n+`)
)

// Text converts PlexTrac's rich-text HTML to readable Markdown-ish text:
// paragraphs, list items, links, bold and code survive; other markup is dropped.
func Text(s string) string {
	if !strings.Contains(s, "<") {
		return strings.TrimSpace(html.UnescapeString(s))
	}
	s = reLink.ReplaceAllStringFunc(s, func(m string) string {
		p := reLink.FindStringSubmatch(m)
		label := strings.TrimSpace(reTag.ReplaceAllString(p[2], ""))
		if label == "" || label == p[1] {
			return p[1]
		}
		return "[" + label + "](" + p[1] + ")"
	})
	s = reBold.ReplaceAllString(s, "**$2**")
	s = reCode.ReplaceAllString(s, "`$1`")
	s = reBreak.ReplaceAllString(s, "\n")
	s = reItem.ReplaceAllString(s, "\n- ")
	s = reCell.ReplaceAllString(s, " | ")
	s = reBlock.ReplaceAllString(s, "\n\n")
	s = reTag.ReplaceAllString(s, "")
	s = html.UnescapeString(s)
	s = strings.ReplaceAll(s, " ", " ")
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = strings.TrimSpace(reSpaces.ReplaceAllString(l, " "))
	}
	s = strings.Join(lines, "\n")
	s = reBlank.ReplaceAllString(s, "\n\n")
	return strings.TrimSpace(s)
}

// Markdown renders a write-up as Markdown, ready to read or paste.
func (w *Writeup) Markdown() string {
	var b strings.Builder
	b.WriteString("# " + w.Title + "\n\n")
	meta := []string{}
	if w.Severity != "" {
		meta = append(meta, "**Severity:** "+w.Severity)
	}
	if w.Repository != "" {
		meta = append(meta, "**Repository:** "+w.Repository)
	}
	meta = append(meta, "**ID:** "+w.ID)
	b.WriteString(strings.Join(meta, " | ") + "\n")
	section := func(title, body string) {
		if t := Text(body); t != "" {
			b.WriteString("\n## " + title + "\n\n" + t + "\n")
		}
	}
	section("Description", w.Description)
	section("Recommendations", w.Recommendations)
	section("References", w.References)
	if len(w.CWE)+len(w.CVE) > 0 {
		b.WriteString("\n## Identifiers\n\n" + strings.Join(append(append([]string{}, w.CWE...), w.CVE...), ", ") + "\n")
	}
	for _, label := range sortedKeys(w.Fields) {
		section(label, w.Fields[label])
	}
	if len(w.Tags) > 0 {
		b.WriteString("\n**Tags:** " + strings.Join(w.Tags, ", ") + "\n")
	}
	return b.String()
}
