package browser

import "testing"

func TestClientHints(t *testing.T) {
	h := ClientHints("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.7000.1 Safari/537.36")
	want := map[string]string{
		"Sec-CH-UA":          `"Chromium";v="150", "Not-A.Brand";v="24", "Google Chrome";v="150"`,
		"Sec-CH-UA-Mobile":   "?0",
		"Sec-CH-UA-Platform": `"Windows"`,
	}
	for k, v := range want {
		if h[k] != v {
			t.Errorf("%s = %q, want %q", k, h[k], v)
		}
	}

	android := ClientHints("Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Mobile Safari/537.36")
	if android["Sec-CH-UA-Platform"] != `"Android"` || android["Sec-CH-UA-Mobile"] != "?1" {
		t.Errorf("android: %v", android)
	}

	// Firefox sends no client hints, so they must be stripped (empty values).
	for k, v := range ClientHints("Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0") {
		if v != "" {
			t.Errorf("firefox %s = %q, want empty", k, v)
		}
	}
}

func TestMetadata(t *testing.T) {
	md := Metadata("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.1.2 Safari/537.36")
	if md == nil || md.Platform != "macOS" || md.FullVersionList[0].Version != "151.0.1.2" || md.Mobile {
		t.Fatalf("metadata: %+v", md)
	}
	if navigatorPlatform(md.Platform) != "MacIntel" {
		t.Errorf("navigator.platform = %q", navigatorPlatform(md.Platform))
	}
}
