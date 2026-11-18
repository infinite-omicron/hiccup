// Package bapp finds, downloads and unpacks extensions from PortSwigger's BApp Store.
package bapp

import (
	"archive/zip"
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/infinite-omicron/hiccup/internal/config"
)

// StoreURL is the BApp Store; tests point it at a local server.
var StoreURL = "https://portswigger.net/bappstore"

const indexTTL = 24 * time.Hour

type Entry struct {
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

type index struct {
	Fetched time.Time `json:"fetched"`
	Entries []Entry   `json:"entries"`
}

// Manifest is BappManifest.bmf.
type Manifest struct {
	UUID          string
	Name          string
	ExtensionType int // 1 java, 2 python, 3 ruby
	EntryPoint    string
	SerialVersion int
	ScreenVersion string
	ProOnly       bool
}

// Type is the extension type name the proxy expects.
func (m Manifest) Type() string {
	switch m.ExtensionType {
	case 2:
		return "python"
	case 3:
		return "ruby"
	default:
		return "java"
	}
}

// Downloaded is a BApp unpacked on disk.
type Downloaded struct {
	Manifest
	Dir   string `json:"dir"`
	Entry string `json:"entry"` // absolute path of the file Burp loads
}

func Dir() string { return filepath.Join(config.Home(), "bapps") }

var client = &http.Client{Timeout: 2 * time.Minute}

func get(ctx context.Context, url string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "hiccup (+https://github.com/infinite-omicron/hiccup)")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		resp.Body.Close()
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return resp, nil
}

func getString(ctx context.Context, url string) (string, error) {
	resp, err := get(ctx, url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	return string(b), err
}

var entryRe = regexp.MustCompile(`href="/bappstore/([0-9a-f]{32})"[^>]*>([^<]+)</a>`)

// Index returns the store's BApps, cached for a day under ~/.hiccup/bapps.
func Index(ctx context.Context, refresh bool) ([]Entry, error) {
	cache := filepath.Join(Dir(), "index.json")
	var idx index
	if !refresh {
		if b, err := os.ReadFile(cache); err == nil && json.Unmarshal(b, &idx) == nil && time.Since(idx.Fetched) < indexTTL {
			return idx.Entries, nil
		}
	}
	page, err := getString(ctx, StoreURL)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	idx = index{Fetched: time.Now().UTC()}
	for _, m := range entryRe.FindAllStringSubmatch(page, -1) {
		name := strings.TrimSpace(html.UnescapeString(m[2]))
		if !seen[m[1]] && name != "" {
			seen[m[1]] = true
			idx.Entries = append(idx.Entries, Entry{UUID: m[1], Name: name})
		}
	}
	if len(idx.Entries) == 0 {
		return nil, fmt.Errorf("no BApps found at %s (page layout changed?)", StoreURL)
	}
	sort.Slice(idx.Entries, func(i, j int) bool {
		return strings.ToLower(idx.Entries[i].Name) < strings.ToLower(idx.Entries[j].Name)
	})
	if err := os.MkdirAll(Dir(), 0o700); err == nil {
		if b, err := json.Marshal(idx); err == nil {
			_ = os.WriteFile(cache, b, 0o600)
		}
	}
	return idx.Entries, nil
}

// Search returns entries whose name contains q (case-insensitive).
func Search(entries []Entry, q string) []Entry {
	var out []Entry
	for _, e := range entries {
		if strings.Contains(strings.ToLower(e.Name), strings.ToLower(q)) {
			out = append(out, e)
		}
	}
	return out
}

// Find resolves a UUID, an exact name (case-insensitive) or a unique substring.
func Find(entries []Entry, q string) (Entry, error) {
	for _, e := range entries {
		if e.UUID == strings.ToLower(q) || strings.EqualFold(e.Name, q) {
			return e, nil
		}
	}
	matches := Search(entries, q)
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return Entry{}, fmt.Errorf("no BApp matches %q (try: hiccup bapp search %s)", q, q)
	default:
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, m.Name)
		}
		return Entry{}, fmt.Errorf("%q matches several BApps: %s", q, strings.Join(names, ", "))
	}
}

// LatestSerial reads the current download serial from the BApp's store page.
func LatestSerial(ctx context.Context, uuid string) (int, error) {
	page, err := getString(ctx, StoreURL+"/"+uuid)
	if err != nil {
		return 0, err
	}
	m := regexp.MustCompile(`bappstore/bapps/download/` + uuid + `/(\d+)`).FindStringSubmatch(page)
	if m == nil {
		return 0, fmt.Errorf("no download link on the store page of %s", uuid)
	}
	return strconv.Atoi(m[1])
}

// Download fetches and unpacks a BApp into ~/.hiccup/bapps/<uuid>/<serial>,
// reusing an earlier download of the same serial.
func Download(ctx context.Context, e Entry) (*Downloaded, error) {
	serial, err := LatestSerial(ctx, e.UUID)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(Dir(), e.UUID, strconv.Itoa(serial))
	if _, err := os.Stat(filepath.Join(dir, "BappManifest.bmf")); err != nil {
		archive := dir + ".bapp"
		if err := fetch(ctx, fmt.Sprintf("%s/bapps/download/%s/%d", StoreURL, e.UUID, serial), archive); err != nil {
			return nil, err
		}
		if err := unzip(archive, dir); err != nil {
			return nil, fmt.Errorf("%s: %w", archive, err)
		}
	}
	return Open(dir)
}

// Open reads an unpacked BApp.
func Open(dir string) (*Downloaded, error) {
	f, err := os.Open(filepath.Join(dir, "BappManifest.bmf"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	m, err := ParseManifest(f)
	if err != nil {
		return nil, err
	}
	if m.EntryPoint == "" {
		return nil, fmt.Errorf("%s: manifest has no EntryPoint", dir)
	}
	entry := filepath.Join(dir, filepath.FromSlash(m.EntryPoint))
	if !within(dir, entry) {
		return nil, fmt.Errorf("%s: EntryPoint escapes the BApp directory", dir)
	}
	if _, err := os.Stat(entry); err != nil {
		return nil, fmt.Errorf("%s: entry point: %w", dir, err)
	}
	return &Downloaded{Manifest: m, Dir: dir, Entry: entry}, nil
}

func ParseManifest(r io.Reader) (Manifest, error) {
	var m Manifest
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		k, v, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		v = strings.TrimSpace(v)
		switch strings.TrimSpace(k) {
		case "Uuid":
			m.UUID = v
		case "Name":
			m.Name = v
		case "ExtensionType":
			m.ExtensionType, _ = strconv.Atoi(v)
		case "EntryPoint":
			m.EntryPoint = v
		case "SerialVersion":
			m.SerialVersion, _ = strconv.Atoi(v)
		case "ScreenVersion":
			m.ScreenVersion = v
		case "ProOnly":
			m.ProOnly = strings.EqualFold(v, "true")
		}
	}
	return m, sc.Err()
}

func fetch(ctx context.Context, url, dst string) error {
	resp, err := get(ctx, url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	tmp := dst + ".part"
	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, io.LimitReader(resp.Body, 512<<20)); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

// unzip extracts archive into dir, refusing entries that would land outside it.
func unzip(archive, dir string) error {
	zr, err := zip.OpenReader(archive)
	if err != nil {
		return err
	}
	defer zr.Close()
	tmp := dir + ".tmp"
	_ = os.RemoveAll(tmp)
	for _, f := range zr.File {
		dst := filepath.Join(tmp, filepath.FromSlash(f.Name))
		if !within(tmp, dst) {
			return fmt.Errorf("entry %q escapes the archive", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(dst, 0o700); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err == nil {
			_, err = io.Copy(out, io.LimitReader(rc, 512<<20))
			if cerr := out.Close(); err == nil {
				err = cerr
			}
		}
		rc.Close()
		if err != nil {
			return err
		}
	}
	_ = os.RemoveAll(dir)
	return os.Rename(tmp, dir)
}

func within(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// MavenURL is Maven Central; tests point it at a local server.
var MavenURL = "https://repo1.maven.org/maven2"

// MavenJar downloads the latest release of group:artifact into ~/.hiccup/<sub>,
// reusing an earlier download. Used for Jython and JRuby.
func MavenJar(ctx context.Context, group, artifact, sub string) (string, error) {
	base := MavenURL + "/" + strings.ReplaceAll(group, ".", "/") + "/" + artifact
	meta, err := getString(ctx, base+"/maven-metadata.xml")
	if err != nil {
		return "", err
	}
	version := latestStable(meta)
	if version == "" {
		return "", fmt.Errorf("%s:%s: no stable version in maven-metadata.xml", group, artifact)
	}
	name := fmt.Sprintf("%s-%s.jar", artifact, version)
	dst := filepath.Join(config.Home(), sub, name)
	if _, err := os.Stat(dst); err == nil {
		return dst, nil
	}
	return dst, fetch(ctx, fmt.Sprintf("%s/%s/%s", base, version, name), dst)
}

var stableRe = regexp.MustCompile(`^\d+(\.\d+)*$`)

// latestStable picks the highest purely numeric version (skipping rc, beta,
// SNAPSHOT) from maven-metadata.xml; <release> can be a release candidate.
func latestStable(meta string) string {
	best, bestParts := "", []int(nil)
	for _, m := range regexp.MustCompile(`<version>([^<]+)</version>`).FindAllStringSubmatch(meta, -1) {
		v := strings.TrimSpace(m[1])
		if !stableRe.MatchString(v) {
			continue
		}
		var parts []int
		for _, p := range strings.Split(v, ".") {
			n, _ := strconv.Atoi(p)
			parts = append(parts, n)
		}
		if bestParts == nil || slices.Compare(parts, bestParts) > 0 {
			best, bestParts = v, parts
		}
	}
	return best
}
