package authmatrix

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"

	"github.com/xuri/excelize/v2"

	"github.com/infinite-omicron/hiccup/internal/backend"
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

// XLSXOptions place the matrix in a workbook. With Template set, the named
// sheet of that workbook (e.g. the "Auth Matrix" tab of Checklist.xltx) is
// filled in its layout: B1 "Action:", one column pair per action from C
// (name in row 1, "Exp?"/"Actual" in row 2), "Account" in A3, accounts from A4.
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

	set := func(col, row int, v any, style int) {
		cell, _ := excelize.CoordinatesToCellName(col, row)
		_ = f.SetCellValue(sh, cell, v)
		if style != 0 {
			_ = f.SetCellStyle(sh, cell, cell, style)
		}
	}
	set(2, 1, "Action:", 0)
	set(1, 3, "Account", 0)
	for i, a := range m.Accounts {
		set(1, 4+i, a.Name, 0)
		set(2, 4+i, fmt.Sprintf("%s (%d)", a.Role, a.Level), wrap)
	}
	_ = f.SetColWidth(sh, "A", "A", 14)
	_ = f.SetColWidth(sh, "B", "B", 14)
	for ai, act := range m.Actions {
		col := 3 + 2*ai
		set(col, 1, act.Name, headerStyle)
		c1, _ := excelize.CoordinatesToCellName(col, 1)
		c2, _ := excelize.CoordinatesToCellName(col+1, 1)
		_ = f.MergeCell(sh, c1, c2)
		set(col, 2, "Exp?", headerStyle)
		set(col+1, 2, "Actual", headerStyle)
		cn1, _ := excelize.ColumnNumberToName(col)
		cn2, _ := excelize.ColumnNumberToName(col + 1)
		_ = f.SetColWidth(sh, cn1, cn2, 34)
		for i, a := range m.Accounts {
			var exp, act2 []string
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
						if worst == "" || worst == "review" {
							worst = c.Finding
						}
					}
					act2 = append(act2, req+" → "+line)
				}
			}
			style := wrap
			switch {
			case worst == "review":
				style = amber
			case worst != "":
				style = red
			}
			set(col, 4+i, strings.Join(exp, "\n"), wrap)
			set(col+1, 4+i, strings.Join(act2, "\n"), style)
		}
	}
	if idx, err := f.GetSheetIndex(sh); err == nil {
		f.SetActiveSheet(idx)
	}
	return f.SaveAs(path)
}

// Issues turns findings into Burp issues, with the owner's and the other
// account's request/response as evidence.
func (m *Matrix) Issues() []backend.Issue {
	accounts := map[string]Account{}
	for _, a := range m.Accounts {
		accounts[a.Name] = a
	}
	titles := map[string]string{
		"vertical":          "Vertical privilege escalation",
		"horizontal":        "Horizontal privilege escalation (IDOR)",
		"forceful-browsing": "Unauthenticated access (forceful browsing)",
	}
	var out []backend.Issue
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
		is := backend.Issue{
			Name:        titles[f.Cell.Finding],
			URL:         f.Request.URL,
			Severity:    "HIGH",
			Confidence:  "TENTATIVE",
			Detail:      detail,
			Remediation: "Enforce authorization on the server for every request: check the caller's role and that they own the referenced object.",
		}
		if owner != nil && owner.RequestB64 != "" {
			is.Evidence = append(is.Evidence, backend.Evidence{URL: f.Request.URL, RequestB64: owner.RequestB64, ResponseB64: owner.ResponseB64})
		}
		if f.Cell.RequestB64 != "" {
			is.Evidence = append(is.Evidence, backend.Evidence{URL: f.Request.URL, RequestB64: f.Cell.RequestB64, ResponseB64: f.Cell.ResponseB64})
		}
		out = append(out, is)
	}
	return out
}
