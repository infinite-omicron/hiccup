package browser

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"time"
)

// Relay serves ep's DevTools HTTP endpoint on listen, adding the auth header,
// for CDP clients that can't send custom headers. Websocket upgrades are proxied
// too. It blocks until ctx is done.
func Relay(ctx context.Context, listen string, ep Endpoint, ready func(addr string)) error {
	target, err := url.Parse(ep.HTTP)
	if err != nil {
		return err
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			// Chromium only accepts an IP or localhost Host header.
			r.Out.Host = target.Host
			if ep.Token != "" {
				r.Out.Header.Set(AuthHeader, ep.Token)
			}
		},
	}
	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: proxy, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdown)
	}()
	ready(ln.Addr().String())
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
