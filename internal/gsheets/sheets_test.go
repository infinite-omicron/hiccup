package gsheets

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/infinite-omicron/hiccup/internal/authmatrix"
)

func TestSpreadsheetID(t *testing.T) {
	for in, want := range map[string]string{
		"1AbC_d-9": "1AbC_d-9",
		"https://docs.google.com/spreadsheets/d/1AbC_d-9/edit#gid=0": "1AbC_d-9",
	} {
		if got := SpreadsheetID(in); got != want {
			t.Errorf("SpreadsheetID(%q) = %q", in, got)
		}
	}
}

func TestWrite(t *testing.T) {
	var calls []string
	var values struct{ Values [][]string }
	var formats []map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.EscapedPath())
		body, _ := io.ReadAll(r.Body)
		switch {
		case r.Method == "GET":
			io.WriteString(w, `{"sheets":[{"properties":{"sheetId":0,"title":"Check List"}}]}`)
		case strings.HasSuffix(r.URL.Path, ":batchUpdate") && strings.Contains(string(body), "addSheet"):
			io.WriteString(w, `{"replies":[{"addSheet":{"properties":{"sheetId":42}}}]}`)
		case strings.HasSuffix(r.URL.Path, ":batchUpdate"):
			var req struct{ Requests []map[string]any }
			_ = json.Unmarshal(body, &req)
			formats = req.Requests
			io.WriteString(w, `{}`)
		case r.Method == "PUT":
			_ = json.Unmarshal(body, &values)
			io.WriteString(w, `{}`)
		default:
			io.WriteString(w, `{}`)
		}
	}))
	defer srv.Close()
	APIURL = srv.URL

	m := &authmatrix.Matrix{
		Accounts: []authmatrix.Account{{Name: "admin1", Role: "admin", Level: 100}, {Name: "user1", Role: "user", Level: 10}},
		Actions: []authmatrix.ActionResult{{Name: "Users", Requests: []authmatrix.RequestResult{{
			RecordedRequest: authmatrix.RecordedRequest{Method: "GET", Template: "/admin/users"},
			Recorder:        "admin1",
			Cells: []authmatrix.Cell{
				{Account: "admin1", Expected: "allow", Verdict: "allowed", Status: 200},
				{Account: "user1", Expected: "deny", Verdict: "allowed", Status: 200, Finding: "vertical"},
			},
		}}}},
	}
	link, err := Write(context.Background(), srv.Client(), "https://docs.google.com/spreadsheets/d/SHEET123/edit", "", m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(link, "SHEET123") || !strings.Contains(link, "gid=42") {
		t.Errorf("link: %s", link)
	}
	if len(calls) != 5 || !strings.HasPrefix(calls[2], "POST /SHEET123/values/") || !strings.HasSuffix(calls[2], ":clear") {
		t.Errorf("calls: %v", calls)
	}
	if values.Values[0][1] != "Action:" || values.Values[0][2] != "Users" || values.Values[1][3] != "Actual" ||
		values.Values[2][0] != "Account" || values.Values[4][0] != "user1" || !strings.Contains(values.Values[4][3], "VERTICAL") {
		t.Errorf("values: %v", values.Values)
	}
	for _, row := range values.Values {
		if len(row) != 4 {
			t.Errorf("row %v should span columns A-D", row)
		}
	}
	var merged, green, yellow, bold int
	for _, f := range formats {
		if _, ok := f["mergeCells"]; ok {
			merged++
		}
		b, _ := json.Marshal(f)
		js := string(b)
		switch {
		case strings.Contains(js, fmt.Sprint(rgb(authmatrix.MatchFill)["green"])):
			green++
		case strings.Contains(js, fmt.Sprint(rgb(authmatrix.MismatchFill)["green"])):
			yellow++
		case strings.Contains(js, `"bold":true`):
			bold++
		}
	}
	// admin1 allowed as expected (green); user1 reached /admin/users, which it shouldn't (yellow).
	if merged != 0 || green != 1 || yellow != 1 || bold != 5 {
		t.Errorf("merged %d, green rows %d, yellow rows %d, bold headers %d", merged, green, yellow, bold)
	}
}
