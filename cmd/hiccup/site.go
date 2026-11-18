package main

import (
	"context"
	"strings"

	"github.com/infinite-omicron/hiccup/internal/backend"
	"github.com/infinite-omicron/hiccup/internal/browser"
	"github.com/infinite-omicron/hiccup/internal/config"
)

// throttleRules converts a throttle config into one rule per host.
func throttleRules(hosts []string, t *config.Throttle) []backend.ThrottleRule {
	if t == nil || t.RPS <= 0 {
		return nil
	}
	var rules []backend.ThrottleRule
	for _, h := range hosts {
		r := backend.ThrottleRule{Host: h, RPS: t.RPS, Burst: t.Burst, JitterMS: t.JitterMS}
		r.Backoff.OnStatus = []int{429, 503}
		r.Backoff.HonorRetryAfter = true
		r.Backoff.MaxS = 120
		if b := t.Backoff; b != nil {
			if len(b.OnStatus) > 0 {
				r.Backoff.OnStatus = b.OnStatus
			}
			r.Backoff.HonorRetryAfter = b.HonorRetryAfter
			if b.MaxS > 0 {
				r.Backoff.MaxS = b.MaxS
			}
		}
		rules = append(rules, r)
	}
	return rules
}

func uaSetting(ua, scope string) backend.UserAgent {
	if scope == "" {
		scope = "browser"
	}
	return backend.UserAgent{UA: ua, Scope: scope, ClientHints: browser.ClientHints(ua)}
}

// applySites pushes every site's throttle to the backend, and the selected
// site's User-Agent. Throttles are additive so that no configured site is ever
// hit faster than its limit, whichever site is "current".
func (a *app) applySites(ctx context.Context, b backend.Backend) (map[string]any, error) {
	var rules []backend.ThrottleRule
	for _, name := range a.cfg.SiteNames() {
		s := a.cfg.Sites[name]
		t, err := s.EffectiveThrottle()
		if err != nil {
			return nil, err
		}
		rules = append(rules, throttleRules(s.Hosts(), t)...)
	}
	out := map[string]any{}
	if len(rules) > 0 {
		applied, err := b.SetThrottle(ctx, rules)
		if err != nil {
			return nil, err
		}
		out["throttle"] = applied
	}
	if _, s, err := a.cfg.Site(a.site); err == nil {
		if ua := s.EffectiveUserAgent(); ua != nil && strings.TrimSpace(ua.Value) != "" {
			setting := uaSetting(ua.Value, ua.Scope)
			if err := b.SetUserAgent(ctx, setting); err != nil {
				return nil, err
			}
			out["user_agent"] = setting
		}
	}
	return out, nil
}

// siteUA is the UA configured for the selected site, if any.
func (a *app) siteUA() string {
	if _, s, err := a.cfg.Site(a.site); err == nil {
		if ua := s.EffectiveUserAgent(); ua != nil {
			return ua.Value
		}
	}
	return ""
}
