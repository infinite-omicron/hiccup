package gsheets

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/infinite-omicron/hiccup/internal/authmatrix"
)

// APIURL is the Sheets API; tests point it at a local server.
var APIURL = "https://sheets.googleapis.com/v4/spreadsheets"

var idRe = regexp.MustCompile(`/spreadsheets/d/([A-Za-z0-9_-]+)`)

// SpreadsheetID accepts a spreadsheet ID or its URL.
func SpreadsheetID(s string) string {
	if m := idRe.FindStringSubmatch(s); m != nil {
		return m[1]
	}
	return s
}

type api struct {
	http *http.Client
	id   string
}

func (a *api) call(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, APIURL+"/"+a.id+path, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct{ Message string } `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error.Message == "" {
			e.Error.Message = strings.TrimSpace(string(data))
		}
		return fmt.Errorf("google sheets: %s: %s", resp.Status, e.Error.Message)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

func rgb(hex string) map[string]float64 {
	var r, g, b int
	fmt.Sscanf(hex, "%02x%02x%02x", &r, &g, &b)
	return map[string]float64{"red": float64(r) / 255, "green": float64(g) / 255, "blue": float64(b) / 255}
}

// Write fills the named tab of the spreadsheet with the matrix grid (creating
// the tab if needed), replacing its previous contents and formatting.
func Write(ctx context.Context, client *http.Client, spreadsheet, sheet string, m *authmatrix.Matrix) (string, error) {
	if sheet == "" {
		sheet = "Auth Matrix"
	}
	a := &api{http: client, id: SpreadsheetID(spreadsheet)}

	var meta struct {
		SpreadsheetURL string `json:"spreadsheetUrl"`
		Sheets         []struct {
			Properties struct {
				SheetID int64  `json:"sheetId"`
				Title   string `json:"title"`
			} `json:"properties"`
		} `json:"sheets"`
	}
	if err := a.call(ctx, "GET", "?fields=spreadsheetUrl,sheets.properties(sheetId,title)", nil, &meta); err != nil {
		return "", err
	}
	sheetID := int64(-1)
	for _, s := range meta.Sheets {
		if s.Properties.Title == sheet {
			sheetID = s.Properties.SheetID
		}
	}
	if sheetID < 0 {
		var res struct {
			Replies []struct {
				AddSheet struct {
					Properties struct {
						SheetID int64 `json:"sheetId"`
					} `json:"properties"`
				} `json:"addSheet"`
			} `json:"replies"`
		}
		add := map[string]any{"requests": []any{map[string]any{"addSheet": map[string]any{"properties": map[string]any{"title": sheet}}}}}
		if err := a.call(ctx, "POST", ":batchUpdate", add, &res); err != nil {
			return "", err
		}
		sheetID = res.Replies[0].AddSheet.Properties.SheetID
	}

	g := m.Grid()
	quoted := "'" + strings.ReplaceAll(sheet, "'", "''") + "'"
	if err := a.call(ctx, "POST", "/values/"+url.PathEscape(quoted)+":clear", map[string]any{}, nil); err != nil {
		return "", err
	}
	values := map[string]any{"range": quoted + "!A1", "majorDimension": "ROWS", "values": g.Rows}
	if err := a.call(ctx, "PUT", "/values/"+url.PathEscape(quoted+"!A1")+"?valueInputOption=RAW", values, nil); err != nil {
		return "", err
	}

	cols := authmatrix.GridCols
	rng := func(r1, c1, r2, c2 int) map[string]any {
		return map[string]any{"sheetId": sheetID, "startRowIndex": r1, "endRowIndex": r2, "startColumnIndex": c1, "endColumnIndex": c2}
	}
	format := func(r, c int, f map[string]any, fields string) map[string]any {
		return map[string]any{"repeatCell": map[string]any{"range": rng(r, c, r+1, c+1), "cell": map[string]any{"userEnteredFormat": f}, "fields": fields}}
	}
	reqs := []any{
		// Drop the old layout's merges and formatting, then wrap the account rows.
		map[string]any{"unmergeCells": map[string]any{"range": map[string]any{"sheetId": sheetID}}},
		map[string]any{"repeatCell": map[string]any{"range": map[string]any{"sheetId": sheetID},
			"cell":   map[string]any{"userEnteredFormat": map[string]any{"backgroundColor": rgb("FFFFFF"), "textFormat": map[string]any{"bold": false}}},
			"fields": "userEnteredFormat(backgroundColor,textFormat)"}},
		map[string]any{"updateDimensionProperties": map[string]any{
			"range":      map[string]any{"sheetId": sheetID, "dimension": "COLUMNS", "startIndex": 2, "endIndex": cols},
			"properties": map[string]any{"pixelSize": 340}, "fields": "pixelSize"}},
	}
	for _, r := range g.Body {
		f := map[string]any{"wrapStrategy": "WRAP", "verticalAlignment": "TOP"}
		switch g.Status[r] {
		case authmatrix.RowMatch:
			f["backgroundColor"], f["textFormat"] = rgb(authmatrix.MatchFill), map[string]any{"foregroundColor": rgb(authmatrix.MatchText)}
		case authmatrix.RowMismatch:
			f["backgroundColor"], f["textFormat"] = rgb(authmatrix.MismatchFill), map[string]any{"foregroundColor": rgb(authmatrix.MismatchText)}
		}
		reqs = append(reqs, map[string]any{"repeatCell": map[string]any{"range": rng(r, 0, r+1, cols),
			"cell":   map[string]any{"userEnteredFormat": f},
			"fields": "userEnteredFormat(wrapStrategy,verticalAlignment,backgroundColor,textFormat.foregroundColor)"}})
	}
	for rc := range g.Headers {
		reqs = append(reqs, format(rc[0], rc[1], map[string]any{"textFormat": map[string]any{"bold": true}}, "userEnteredFormat.textFormat.bold"))
	}
	if err := a.call(ctx, "POST", ":batchUpdate", map[string]any{"requests": reqs}, nil); err != nil {
		return "", err
	}
	return fmt.Sprintf("https://docs.google.com/spreadsheets/d/%s/edit#gid=%d", a.id, sheetID), nil
}
