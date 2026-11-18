// Package m365 uploads files to OneDrive and SharePoint through Microsoft Graph,
// signing in with the OAuth device-code flow.
package m365

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/infinite-omicron/hiccup/internal/config"
)

// Scopes: read and write the files the user can reach (OneDrive and
// SharePoint), plus a refresh token. Files.ReadWrite.All is consentable by users.
var Scopes = []string{"offline_access", "https://graph.microsoft.com/Files.ReadWrite.All"}

// GraphURL is Microsoft Graph, and Authority the Microsoft identity platform;
// tests point them at a local server.
var (
	GraphURL  = "https://graph.microsoft.com/v1.0"
	Authority = "https://login.microsoftonline.com"
)

// Settings identify the Entra (Azure AD) app registration hiccup signs in with.
type Settings struct {
	Tenant   string // "organizations", "common", a tenant ID or a domain
	ClientID string // a public client with "Allow public client flows" enabled
}

func (s Settings) oauth() (*oauth2.Config, error) {
	if s.ClientID == "" {
		return nil, errors.New(`no Microsoft client ID: register an app in Entra ID (public client, "Allow public client flows"), then set "microsoft": {"client_id": "..."} in config or HICCUP_M365_CLIENT_ID`)
	}
	tenant := s.Tenant
	if tenant == "" {
		tenant = "organizations"
	}
	base := Authority + "/" + url.PathEscape(tenant) + "/oauth2/v2.0"
	return &oauth2.Config{ClientID: s.ClientID, Scopes: Scopes, Endpoint: oauth2.Endpoint{
		AuthURL: base + "/authorize", TokenURL: base + "/token", DeviceAuthURL: base + "/devicecode",
		AuthStyle: oauth2.AuthStyleInParams, // public client: no secret, client_id in the form
	}}, nil
}

func tokenPath() string { return filepath.Join(config.Home(), "microsoft", "token.json") }

func saveToken(t *oauth2.Token) error {
	if err := os.MkdirAll(filepath.Dir(tokenPath()), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(t)
	if err != nil {
		return err
	}
	return os.WriteFile(tokenPath(), b, 0o600)
}

// Login runs the device-code flow: announce gets the URL and code to show the
// user, and Login returns once they've signed in.
func Login(ctx context.Context, s Settings, announce func(verificationURL, code string)) error {
	conf, err := s.oauth()
	if err != nil {
		return err
	}
	da, err := conf.DeviceAuth(ctx)
	if err != nil {
		return fmt.Errorf("microsoft sign-in: %w", err)
	}
	announce(da.VerificationURI, da.UserCode)
	tok, err := conf.DeviceAccessToken(ctx, da)
	if err != nil {
		return fmt.Errorf("microsoft sign-in: %w", err)
	}
	return saveToken(tok)
}

// Logout deletes the saved token.
func Logout() error {
	err := os.Remove(tokenPath())
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// Client returns an HTTP client for Graph using the token saved by Login,
// refreshing (and re-saving) it as needed.
func Client(ctx context.Context, s Settings) (*http.Client, error) {
	conf, err := s.oauth()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(tokenPath())
	if err != nil {
		return nil, errors.New("not signed in to Microsoft 365: run `hiccup m365 login`")
	}
	var tok oauth2.Token
	if err := json.Unmarshal(b, &tok); err != nil {
		return nil, err
	}
	return oauth2.NewClient(ctx, &savingSource{base: conf.TokenSource(ctx, &tok), last: tok.AccessToken}), nil
}

type savingSource struct {
	base oauth2.TokenSource
	last string
}

func (s *savingSource) Token() (*oauth2.Token, error) {
	t, err := s.base.Token()
	if err == nil && t.AccessToken != s.last {
		s.last = t.AccessToken
		_ = saveToken(t)
	}
	return t, err
}

// Item is the part of a Graph driveItem hiccup reports.
type Item struct {
	Name   string `json:"name"`
	WebURL string `json:"webUrl"`
	Size   int64  `json:"size"`
	Folder *struct {
		ChildCount int `json:"childCount"`
	} `json:"folder,omitempty"`
	ParentReference struct {
		DriveID string `json:"driveId"`
	} `json:"parentReference"`
	ID           string    `json:"id"`
	LastModified time.Time `json:"lastModifiedDateTime"`
}

func call(ctx context.Context, c *http.Client, method, u string, body io.Reader, contentType string, out any) error {
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error struct{ Code, Message string } `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		if e.Error.Message == "" {
			e.Error.Message = strings.TrimSpace(string(data))
		}
		return fmt.Errorf("microsoft graph: %s: %s %s", resp.Status, e.Error.Code, e.Error.Message)
	}
	if out != nil {
		return json.Unmarshal(data, out)
	}
	return nil
}

// shareID encodes a sharing or document URL for Graph's /shares endpoint.
func shareID(u string) string {
	return "u!" + strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(u)), "=")
}

// escapePath escapes each segment of a drive path for a Graph ":/path:" address.
func escapePath(p string) string {
	segs := strings.Split(strings.Trim(p, "/"), "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// Upload puts the file at local onto target, replacing any existing copy:
//
//   - "onedrive:/Folder/name.xlsx": a path in the signed-in user's OneDrive
//     (a path ending in "/" is a folder, and the file keeps its own name)
//   - an https:// URL of a OneDrive or SharePoint folder, as copied from the
//     browser: the file is uploaded into it under its own name
//   - an https:// URL of an existing file: its content is replaced
func Upload(ctx context.Context, c *http.Client, local, target string) (*Item, error) {
	data, err := os.ReadFile(local)
	if err != nil {
		return nil, err
	}
	const xlsx = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
	name := filepath.Base(local)
	var putURL string
	switch {
	case strings.HasPrefix(target, "onedrive:"):
		p := strings.TrimPrefix(target, "onedrive:")
		if p == "" || strings.HasSuffix(p, "/") {
			p = path.Join(p, name)
		}
		putURL = fmt.Sprintf("%s/me/drive/root:/%s:/content", GraphURL, escapePath(p))
	case strings.HasPrefix(target, "https://"):
		var item Item
		if err := call(ctx, c, "GET", GraphURL+"/shares/"+shareID(target)+"/driveItem", nil, "", &item); err != nil {
			return nil, fmt.Errorf("%s: %w", target, err)
		}
		drive := item.ParentReference.DriveID
		if item.Folder != nil {
			putURL = fmt.Sprintf("%s/drives/%s/items/%s:/%s:/content", GraphURL, url.PathEscape(drive), url.PathEscape(item.ID), url.PathEscape(name))
		} else {
			putURL = fmt.Sprintf("%s/drives/%s/items/%s/content", GraphURL, url.PathEscape(drive), url.PathEscape(item.ID))
		}
	default:
		return nil, fmt.Errorf("%q: want onedrive:/path/file.xlsx or an https:// OneDrive/SharePoint URL", target)
	}
	var item Item
	if err := call(ctx, c, "PUT", putURL, bytes.NewReader(data), xlsx, &item); err != nil {
		return nil, err
	}
	return &item, nil
}

// Me returns who the token belongs to, and their OneDrive's URL.
func Me(ctx context.Context, c *http.Client) (map[string]string, error) {
	var me struct {
		DisplayName       string `json:"displayName"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
	if err := call(ctx, c, "GET", GraphURL+"/me?$select=displayName,userPrincipalName", nil, "", &me); err != nil {
		return nil, err
	}
	out := map[string]string{"user": me.UserPrincipalName, "name": me.DisplayName}
	var drive struct {
		WebURL string `json:"webUrl"`
	}
	if err := call(ctx, c, "GET", GraphURL+"/me/drive?$select=webUrl", nil, "", &drive); err == nil {
		out["onedrive"] = drive.WebURL
	}
	return out, nil
}
