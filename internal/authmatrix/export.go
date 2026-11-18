package authmatrix

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"os"
	"strings"

	"github.com/xuri/excelize/v2"

	"github.com/infinite-omicron/hiccup/internal/proxy"
)

// WriteJSON writes the matrix without the base64 evidence unless full is set.
func (m *Matrix) WriteJSON(w io.Writer, full bool) error {
	out := *m
	if !full {
		out.Actions = make([]ActionResult, len(m.Actions))
		for i, a := range m.Actions {
			out.Actions[i] = ActionResult{Name: a.Name, Requests: make([]RequestResult, len(a.Requests))}
			for j, r := range a.Requests {
				r.Cells = append([]Cell(nil), r.Cells...)
				for k := range r.Cells {
					r.Cells[k].RequestB64, r.Cells[k].ResponseB64 = "", ""
				}
				out.Actions[i].Requests[j] = r
			}
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(&out)
}

func (m *Matrix) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"action", "method", "template", "url", "recorder", "account", "role", "level", "expected", "why", "verdict", "reason", "status", "finding"})
	roles := map[string]Account{}
	for _, a := range m.Accounts {
		roles[a.Name] = a
	}
	for _, act := range m.Actions {
		for _, r := range act.Requests {
			for _, c := range r.Cells {
				a := roles[c.Account]
				_ = cw.Write([]string{act.Name, r.Method, r.Template, r.URL, r.Recorder, c.Account, a.Role, fmt.Sprint(a.Level),
					c.Expected, c.Why, c.Verdict, c.Reason, fmt.Sprint(c.Status), c.Finding})
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

// Row statuses: whether every replayed request in an account's row did what
// was expected (allowed when expected to be allowed, denied when expected to be
// denied). Rows where nothing was replayed have no status.
const (
	RowMatch    = "match"
	RowMismatch = "mismatch"
)

// Grid is the matrix laid out like the Checklist "Auth Matrix" tab, in
// columns A-D with one block per action, stacked top to bottom:
//
//	   A          B         C            D
//	1             Action:   Home
//	2                       Exp?         Actual
//	3  Account
//	4  admin1               allow: ...     GET / -> 200 allowed
//	...  (one row per account), then a blank row and the next action's block.
//
// Coordinates are 0-based [row, col].
type Grid struct {
	Rows [][]string
	// Headers maps header cells to the template cell whose style they copy:
	// "B1" (the "Action:" label), "C1" (the action name), "C2"/"D2"
	// ("Exp?"/"Actual") and "A3" ("Account").
	Headers map[[2]int]string
	// Body lists the account rows, whose Exp?/Actual cells wrap.
	Body []int
	// Status colors account rows: RowMatch (green) or RowMismatch (yellow).
	Status map[int]string
}

// GridCols is the number of columns the grid uses (A-D).
const GridCols = 4

// Row colors (fill and text), as hex RGB: Excel's "Good" green and "Neutral" yellow.
const (
	MatchFill, MatchText       = "C6EFCE", "006100"
	MismatchFill, MismatchText = "FFEB9C", "9C5700"
)

func (m *Matrix) Grid() *Grid {
	g := &Grid{Headers: map[[2]int]string{}, Status: map[int]string{}}
	row := func() int {
		g.Rows = append(g.Rows, make([]string, GridCols))
		return len(g.Rows) - 1
	}
	for ai, act := range m.Actions {
		if ai > 0 {
			row() // blank row between blocks
		}
		r := row()
		g.Rows[r][1], g.Rows[r][2] = "Action:", act.Name
		g.Headers[[2]int{r, 1}], g.Headers[[2]int{r, 2}] = "B1", "C1"
		r = row()
		g.Rows[r][2], g.Rows[r][3] = "Exp?", "Actual"
		g.Headers[[2]int{r, 2}], g.Headers[[2]int{r, 3}] = "C2", "D2"
		r = row()
		g.Rows[r][0] = "Account"
		g.Headers[[2]int{r, 0}] = "A3"
		for _, a := range m.Accounts {
			var exp, actual []string
			matched, mismatched := false, false
			for _, rr := range act.Requests {
				for _, c := range rr.Cells {
					if c.Account != a.Name {
						continue
					}
					req := rr.Key()
					if rr.ObjectRef {
						req += " (" + rr.Recorder + "'s)"
					}
					exp = append(exp, c.Expected+": "+req)
					line := c.Verdict
					if c.Status != 0 {
						line = fmt.Sprintf("%d %s", c.Status, c.Verdict)
					}
					if c.Finding != "" {
						line += " (" + FindingLabel(c.Finding) + ")"
					}
					actual = append(actual, req+" -> "+line)
					switch {
					case c.Verdict == Skipped:
					case (c.Expected == "allow" && c.Verdict == Allowed) || (c.Expected == "deny" && c.Verdict == Denied):
						matched = true
					default:
						mismatched = true
					}
				}
			}
			r = row()
			g.Body = append(g.Body, r)
			g.Rows[r][0] = a.Name
			g.Rows[r][2] = strings.Join(exp, "\n")
			g.Rows[r][3] = strings.Join(actual, "\n")
			switch {
			case mismatched:
				g.Status[r] = RowMismatch
			case matched:
				g.Status[r] = RowMatch
			}
		}
	}
	return g
}

// XLSXOptions place the matrix in a workbook. With Template set, the named
// sheet of that workbook (e.g. the "Auth Matrix" tab of Checklist.xltx) is
// filled in the Grid layout and the rest of the workbook is kept.
type XLSXOptions struct {
	Template string
	Sheet    string
}

func (m *Matrix) WriteXLSX(path string, o XLSXOptions) error {
	if o.Sheet == "" {
		o.Sheet = "Auth Matrix"
	}
	var f *excelize.File
	var err error
	if o.Template != "" {
		if f, err = excelize.OpenFile(o.Template); err != nil {
			return err
		}
	} else {
		f = excelize.NewFile()
		_ = f.SetSheetName("Sheet1", o.Sheet)
	}
	defer f.Close()
	if idx, _ := f.GetSheetIndex(o.Sheet); idx < 0 {
		if _, err := f.NewSheet(o.Sheet); err != nil {
			return err
		}
	}
	sh := o.Sheet
	family, _ := f.GetDefaultFont()
	bold, _ := f.NewStyle(&excelize.Style{Font: &excelize.Font{Family: family, Bold: true}})
	// Header styles come from the template's first block, so every block looks like it.
	headerStyle := map[string]int{}
	for _, cell := range []string{"A3", "B1", "C1", "C2", "D2"} {
		st, _ := f.GetCellStyle(sh, cell)
		if st == 0 {
			st = bold
		}
		headerStyle[cell] = st
	}
	top := &excelize.Alignment{WrapText: true, Vertical: "top"}
	wrap, _ := f.NewStyle(&excelize.Style{Alignment: top, Font: &excelize.Font{Family: family}})
	// Excel's own "Good" and "Neutral" cell colors.
	rowStyle := map[string]int{}
	for status, c := range map[string][2]string{RowMatch: {MatchFill, MatchText}, RowMismatch: {MismatchFill, MismatchText}} {
		rowStyle[status], _ = f.NewStyle(&excelize.Style{Alignment: top,
			Fill: excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{c[0]}}, Font: &excelize.Font{Family: family, Color: c[1]}})
	}

	g := m.Grid()
	name := func(r, c int) string { n, _ := excelize.CoordinatesToCellName(c+1, r+1); return n }
	for r, row := range g.Rows {
		for c, v := range row {
			if v != "" {
				_ = f.SetCellValue(sh, name(r, c), v)
			}
		}
	}
	for _, r := range g.Body {
		style := wrap
		if st, ok := rowStyle[g.Status[r]]; ok {
			style = st
		}
		_ = f.SetCellStyle(sh, name(r, 0), name(r, GridCols-1), style)
	}
	for rc, tmpl := range g.Headers {
		_ = f.SetCellStyle(sh, name(rc[0], rc[1]), name(rc[0], rc[1]), headerStyle[tmpl])
	}
	_ = f.SetColWidth(sh, "A", "A", 14)
	_ = f.SetColWidth(sh, "B", "B", 10)
	_ = f.SetColWidth(sh, "C", "D", 48)
	// Print landscape, one page wide, so Exp? and Actual stay side by side.
	landscape, one, any := "landscape", 1, 0
	_ = f.SetPageLayout(sh, &excelize.PageLayoutOptions{Orientation: &landscape, FitToWidth: &one, FitToHeight: &any})
	fit := true
	_ = f.SetSheetProps(sh, &excelize.SheetPropsOptions{FitToPage: &fit})
	if idx, err := f.GetSheetIndex(sh); err == nil {
		f.SetActiveSheet(idx)
	}
	if err := f.SaveAs(path); err != nil {
		return err
	}
	// The workbook holds findings; excelize creates it executable and world-readable.
	return os.Chmod(path, 0o600)
}

// FindingLabel is how a finding reads in workbooks and Burp issues, e.g.
// "GET /api/export -> 200 allowed (Forceful Browsing)". The classification is
// a heuristic, so escalations are worded as potential. JSON, CSV and
// `matrix run` keep the short codes.
func FindingLabel(finding string) string {
	switch finding {
	case "vertical":
		return "Potential Vertical Privilege Escalation"
	case "horizontal":
		return "Potential Horizontal Privilege Escalation"
	case "forceful-browsing":
		return "Forceful Browsing"
	case "review":
		return "Needs Review"
	}
	return finding
}

// Issues turns findings into Burp issues, with the owner's and the other
// account's request/response as evidence.
func (m *Matrix) Issues() []proxy.Issue {
	accounts := map[string]Account{}
	for _, a := range m.Accounts {
		accounts[a.Name] = a
	}
	var out []proxy.Issue
	for _, f := range m.Findings(false) {
		a := accounts[f.Cell.Account]
		var owner *Cell
		for i := range f.Request.Cells {
			if f.Request.Cells[i].Account == f.Request.Recorder {
				owner = &f.Request.Cells[i]
			}
		}
		detail := fmt.Sprintf(`<p><b>%s</b> (role %s, level %d) was able to replay <code>%s %s</code>, recorded by <b>%s</b> during the action <b>%s</b>.</p>
<p>Expected: %s (%s). Observed: %s (%s).</p>
<p>Found by hiccup's auth matrix; confirm manually before reporting.</p>`,
			html.EscapeString(a.Name), html.EscapeString(a.Role), a.Level,
			html.EscapeString(f.Request.Method), html.EscapeString(f.Request.Template),
			html.EscapeString(f.Request.Recorder), html.EscapeString(f.Action),
			f.Cell.Expected, html.EscapeString(f.Cell.Why), f.Cell.Verdict, html.EscapeString(f.Cell.Reason))
		is := proxy.Issue{
			Name:        FindingLabel(f.Cell.Finding),
			URL:         f.Request.URL,
			Severity:    "HIGH",
			Confidence:  "TENTATIVE",
			Detail:      detail,
			Remediation: "Enforce authorization on the server for every request: check the caller's role and that they own the referenced object.",
		}
		if owner != nil && owner.RequestB64 != "" {
			is.Evidence = append(is.Evidence, proxy.Evidence{URL: f.Request.URL, RequestB64: owner.RequestB64, ResponseB64: owner.ResponseB64})
		}
		if f.Cell.RequestB64 != "" {
			is.Evidence = append(is.Evidence, proxy.Evidence{URL: f.Request.URL, RequestB64: f.Cell.RequestB64, ResponseB64: f.Cell.ResponseB64})
		}
		out = append(out, is)
	}
	return out
}
