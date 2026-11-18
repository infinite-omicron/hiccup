package browser

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/chromedp/cdproto/emulation"
)

var chromeVersion = regexp.MustCompile(`(?:Chrome|Chromium|CriOS)/(\d+)\.([\d.]+)`)

// Metadata derives UA client-hint metadata from a UA string. It returns nil for
// non-Chromium UAs (Firefox and Safari don't send client hints).
func Metadata(ua string) *emulation.UserAgentMetadata {
	m := chromeVersion.FindStringSubmatch(ua)
	if m == nil {
		return nil
	}
	major, full := m[1], m[1]+"."+m[2]
	brands := []*emulation.UserAgentBrandVersion{
		{Brand: "Chromium", Version: major},
		{Brand: "Not-A.Brand", Version: "24"},
		{Brand: "Google Chrome", Version: major},
	}
	fullList := []*emulation.UserAgentBrandVersion{
		{Brand: "Chromium", Version: full},
		{Brand: "Not-A.Brand", Version: "24.0.0.0"},
		{Brand: "Google Chrome", Version: full},
	}
	platform, mobile := "Linux", false
	switch {
	case strings.Contains(ua, "Android"):
		platform, mobile = "Android", strings.Contains(ua, "Mobile")
	case strings.Contains(ua, "Windows"):
		platform = "Windows"
	case strings.Contains(ua, "Macintosh"), strings.Contains(ua, "Mac OS X"):
		platform = "macOS"
	case strings.Contains(ua, "CrOS"):
		platform = "Chrome OS"
	}
	return &emulation.UserAgentMetadata{
		Brands:          brands,
		FullVersionList: fullList,
		Platform:        platform,
		Mobile:          mobile,
		Architecture:    "x86",
		Bitness:         "64",
	}
}

// ClientHints returns the Sec-CH-UA* request headers matching ua. For a
// non-Chromium UA the values are empty, which tells the extension to strip them.
func ClientHints(ua string) map[string]string {
	md := Metadata(ua)
	if md == nil {
		return map[string]string{"Sec-CH-UA": "", "Sec-CH-UA-Mobile": "", "Sec-CH-UA-Platform": ""}
	}
	parts := make([]string, len(md.Brands))
	for i, b := range md.Brands {
		parts[i] = fmt.Sprintf("%q;v=%q", b.Brand, b.Version)
	}
	mobile := "?0"
	if md.Mobile {
		mobile = "?1"
	}
	return map[string]string{
		"Sec-CH-UA":          strings.Join(parts, ", "),
		"Sec-CH-UA-Mobile":   mobile,
		"Sec-CH-UA-Platform": fmt.Sprintf("%q", md.Platform),
	}
}

// navigatorPlatform maps a client-hint platform to the legacy navigator.platform value.
func navigatorPlatform(p string) string {
	switch p {
	case "Windows":
		return "Win32"
	case "macOS":
		return "MacIntel"
	case "Android":
		return "Linux armv8l"
	default:
		return "Linux x86_64"
	}
}
