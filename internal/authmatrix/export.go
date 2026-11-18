package authmatrix

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io"
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

// Highlights for grid cells.
const (
	MarkFinding = "finding"
	MarkReview  = "review"
)

// Grid is the matrix laid out like the Checklist "Auth Matrix" tab: B1
// "Action:", one column pair per action from C (name in row 1, "Exp?" and
// "Actual" in row 2), "Account" in A3, one row per account from row 4.
// Coordinates are 0-based [row, col].
type Grid struct {
	Rows    [][]string
	Header  [][2]int          // action names and Exp?/Actual labels
	Merged  [][2]int          // action name cells, merged with the cell to their right
	Marks   map[[2]int]string // Actual cells with a finding or a review
	DataRow int               // first account row
}

func (m *Matrix) Grid() *Grid {
	cols := 2 + 2*len(m.Actions)
	g := &Grid{Marks: map[[2]int]string{}, DataRow: 3}
	g.Rows = make([][]string, 3+len(m.Accounts))
	for i := range g.Rows {
		g.Rows[i] = make([]string, cols)
	}
	g.Rows[0][1], g.Rows[2][0] = "Action:", "Account"
	for i, a := range m.Accounts {
		g.Rows[3+i][0] = a.Name
		g.Rows[3+i][1] = fmt.Sprintf("%s (%d)", a.Role, a.Level)
	}
	for ai, act := range m.Actions {
		col := 2 + 2*ai
		g.Rows[0][col], g.Rows[1][col], g.Rows[1][col+1] = act.Name, "Exp?", "Actual"
		g.Header = append(g.Header, [2]int{0, col}, [2]int{1, col}, [2]int{1, col + 1})
		g.Merged = append(g.Merged, [2]int{0, col})
		for i, a := range m.Accounts {
			var exp, actual []string
			worst := ""
			for _, r := range act.Requests {
				for _, c := range r.Cells {
					if c.Account != a.Name {
						continue
					}
					req := r.Key()
					if r.ObjectRef {
						req += " (" + r.Recorder + "'s)"
					}
					exp = append(exp, c.Expected+": "+req)
					line := c.Verdict
					if c.Status != 0 {
						line = fmt.Sprintf("%d %s", c.Status, c.Verdict)
					}
					if c.Finding != "" {
						line = strings.ToUpper(c.Finding) + " — " + line
						if worst == "" || worst == MarkReview {
							worst = c.Finding
						}
					}
					actual = append(actual, req+" → "+line)
				}
			}
			g.Rows[3+i][col] = strings.Join(exp, "\n")
			g.Rows[3+i][col+1] = strings.Join(actual, "\n")
			switch worst {
			case "":
			case MarkReview:
				g.Marks[[2]int{3 + i, col + 1}] = MarkReview
			default:
				g.Marks[[2]int{3 + i, col + 1}] = MarkFinding
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
	headerStyle, _ := f.GetCellStyle(sh, "C2")
	if headerStyle == 0 {
		headerStyle, _ = f.NewStyle(&excelize.Style{Font: &excelize.Font{Bold: true}})
	}
	family, _ := f.GetDefaultFont()
	top := &excelize.Alignment{WrapText: true, Vertical: "top"}
	wrap, _ := f.NewStyle(&excelize.Style{Alignment: top, Font: &excelize.Font{Family: family}})
	red, _ := f.NewStyle(&excelize.Style{Alignment: top,
		Fill: excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"F8CBAD"}}, Font: &excelize.Font{Family: family, Bold: true, Color: "9C0006"}})
	amber, _ := f.NewStyle(&excelize.Style{Alignment: top,
		Fill: excelize.Fill{Type: "pattern", Pattern: 1, Color: []string{"FFE699"}}, Font: &excelize.Font{Family: family}})

	g := m.Grid()
	name := func(r, c int) string { n, _ := excelize.CoordinatesToCellName(c+1, r+1); return n }
	for r, row := range g.Rows {
		for c, v := range row {
			if v == "" {
				continue
			}
			_ = f.SetCellValue(sh, name(r, c), v)
			if r >= g.DataRow && c >= 1 {
				_ = f.SetCellStyle(sh, name(r, c), name(r, c), wrap)
			}
		}
	}
	for _, h := range g.Header {
		_ = f.SetCellStyle(sh, name(h[0], h[1]), name(h[0], h[1]), headerStyle)
	}
	for _, mc := range g.Merged {
		_ = f.MergeCell(sh, name(mc[0], mc[1]), name(mc[0], mc[1]+1))
	}
	for rc, mark := range g.Marks {
		style := red
		if mark == MarkReview {
			style = amber
		}
		_ = f.SetCellStyle(sh, name(rc[0], rc[1]), name(rc[0], rc[1]), style)
	}
	_ = f.SetColWidth(sh, "A", "B", 14)
	if len(m.Actions) > 0 {
		last, _ := excelize.ColumnNumberToName(2 + 2*len(m.Actions))
		_ = f.SetColWidth(sh, "C", last, 34)
	}
	if idx, err := f.GetSheetIndex(sh); err == nil {
		f.SetActiveSheet(idx)
	}
	return f.SaveAs(path)
}

// Issues turns findings into Burp issues, with the owner's and the other
// account's request/response as evidence.
func (m *Matrix) Issues() []proxy.Issue {
	accounts := map[string]Account{}
	for _, a := range m.Accounts {
		accounts[a.Name] = a
	}
	titles := map[string]string{
		"vertical":          "Vertical privilege escalation",
		"horizontal":        "Horizontal privilege escalation (IDOR)",
		"forceful-browsing": "Unauthenticated access (forceful browsing)",
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
			Name:        titles[f.Cell.Finding],
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
