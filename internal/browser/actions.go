package browser

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/chromedp"
)

// LoginRecipe is a form login: fill username and password, click submit, then
// wait until the URL contains SuccessURL or SuccessSelector appears.
type LoginRecipe struct {
	URL             string
	UsernameSel     string
	PasswordSel     string
	SubmitSel       string
	Username        string
	Password        string
	SuccessURL      string
	SuccessSelector string
}

// Login runs a recipe in this tab.
func (s *Session) Login(r LoginRecipe, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(s.Ctx, timeout)
	defer cancel()
	if err := chromedp.Do(ctx,
		chromedp.Navigate(r.URL),
		chromedp.WaitVisible(chromedp.CSS(r.UsernameSel)),
		chromedp.SendKeys(chromedp.CSS(r.UsernameSel), r.Username),
		chromedp.SendKeys(chromedp.CSS(r.PasswordSel), r.Password),
		chromedp.Click(chromedp.CSS(r.SubmitSel)),
	); err != nil {
		return fmt.Errorf("login form: %w", err)
	}
	if err := s.WaitLoggedIn(ctx, r.SuccessURL, r.SuccessSelector); err != nil {
		return fmt.Errorf("login did not succeed: %w", err)
	}
	return nil
}

// WaitLoggedIn polls until the URL contains urlContains (when set) and
// selector exists (when set). With neither set, it waits for the URL to leave
// the page it was on.
func (s *Session) WaitLoggedIn(ctx context.Context, urlContains, selector string) error {
	start, _ := chromedp.Run(s.Ctx, chromedp.Location())
	for {
		loc, err := chromedp.Run(ctx, chromedp.Location())
		if err != nil {
			return err
		}
		ok := true
		if urlContains != "" {
			ok = strings.Contains(loc, urlContains)
		} else if selector == "" {
			ok = loc != start
		}
		if ok && selector != "" {
			n, err := chromedp.Run(ctx, chromedp.Evaluate[bool](fmt.Sprintf("document.querySelector(%q) !== null", selector)))
			ok = err == nil && n
		}
		if ok {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// Cookies returns the cookies the browser would send to urls.
func (s *Session) Cookies(urls ...string) ([]*network.Cookie, error) {
	res, err := chromedp.Call(s.Ctx, network.GetCookies, network.GetCookiesParams{URLs: urls})
	if err != nil {
		return nil, err
	}
	return res.Cookies, nil
}

// Link is a navigation link found on a page. Path is its place in the menu,
// outermost first, ending with the link's own text: e.g. ["Content",
// "Scheduled content"] for a link in the Content menu's submenu.
type Link struct {
	Path []string `json:"path"`
	Text string   `json:"text"`
	Href string   `json:"href"`
}

// navLinksJS collects same-origin links matching a selector, with their menu
// path. A link's path comes from the menus around it: the label of each
// enclosing <li> (its first link, button or span), the <summary> of an
// enclosing <details>, and the element whose aria-controls names an
// enclosing element. textContent is used so links in collapsed or
// hover-only submenus are found too.
const navLinksJS = `((sel) => {
	const clean = s => (s || "").replace(/\s+/g, " ").trim();
	const label = el => clean(el.textContent) || clean(el.getAttribute("aria-label")) || clean(el.getAttribute("title"));
	const liLabel = li => {
		for (const c of li.children) {
			if (c.matches("a, button, span, summary, [role=menuitem], [role=button]")) {
				const t = label(c);
				if (t) return t;
			}
		}
		return "";
	};
	const seen = new Set(), out = [];
	for (const a of document.querySelectorAll(sel)) {
		if (!a.href || a.origin !== location.origin) continue;
		const href = a.href.split("#")[0];
		if (seen.has(href)) continue;
		seen.add(href);
		const text = label(a) || a.pathname;
		const path = [];
		const own = a.closest("li");
		for (let n = own ? own.parentElement : a.parentElement; n && n !== document.body; n = n.parentElement) {
			let t = "";
			if (n.tagName === "LI") {
				t = liLabel(n);
			} else if (n.tagName === "DETAILS") {
				const s = n.querySelector(":scope > summary");
				t = s ? label(s) : "";
			} else if (n.id) {
				const ctl = document.querySelector("[aria-controls='" + CSS.escape(n.id) + "']");
				if (ctl && !ctl.contains(a)) t = label(ctl);
			}
			if (t && t !== path[0] && t !== text) path.unshift(t);
		}
		path.push(text);
		out.push({path, text, href});
	}
	return out;
})`

// Links returns the distinct same-origin links matching selector on the
// current page, each with its menu path.
func (s *Session) Links(selector string) ([]Link, error) {
	js := fmt.Sprintf("%s(%q)", navLinksJS, selector)
	links, err := chromedp.Run(s.Ctx, chromedp.Evaluate[[]Link](js))
	if errors.Is(err, chromedp.ErrJSNull) {
		return nil, nil
	}
	return links, err
}
