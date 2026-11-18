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

// Link is a navigation link found on a page.
type Link struct {
	Text string `json:"text"`
	Href string `json:"href"`
}

// Links returns the distinct same-origin links matching selector on the current page.
func (s *Session) Links(selector string) ([]Link, error) {
	js := fmt.Sprintf(`(() => {
		const seen = new Set(), out = [];
		for (const a of document.querySelectorAll(%q)) {
			if (!a.href || a.origin !== location.origin || seen.has(a.href)) continue;
			seen.add(a.href);
			const text = (a.innerText || a.title || a.getAttribute("aria-label") || a.pathname).trim().replace(/\s+/g, " ");
			out.push({text, href: a.href});
		}
		return out;
	})()`, selector)
	links, err := chromedp.Run(s.Ctx, chromedp.Evaluate[[]Link](js))
	if errors.Is(err, chromedp.ErrJSNull) {
		return nil, nil
	}
	return links, err
}
