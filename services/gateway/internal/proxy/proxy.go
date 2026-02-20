package proxy

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

type target struct {
	proxy       *httputil.ReverseProxy
	stripPrefix string // strip this prefix before forwarding
}

type Proxy struct {
	targets map[string]*target
}

func NewProxy() *Proxy {
	return &Proxy{
		targets: make(map[string]*target),
	}
}

// AddTarget registers a service target.
// stripPrefix: the gateway path prefix to strip before forwarding (e.g. "/api/auth")
func (p *Proxy) AddTarget(name string, targetURL string, stripPrefix string) error {
	u, err := url.Parse(targetURL)
	if err != nil {
		return err
	}

	rp := httputil.NewSingleHostReverseProxy(u)

	// Custom director to rewrite path
	defaultDirector := rp.Director
	rp.Director = func(req *http.Request) {
		defaultDirector(req)
		if stripPrefix != "" {
			req.URL.Path = strings.TrimPrefix(req.URL.Path, stripPrefix)
			if req.URL.Path == "" {
				req.URL.Path = "/"
			}
			req.URL.RawPath = req.URL.Path
		}
	}

	p.targets[name] = &target{proxy: rp, stripPrefix: stripPrefix}
	log.Printf("Registered proxy target: %s -> %s (strip: %s)", name, targetURL, stripPrefix)
	return nil
}

func (p *Proxy) Forward(name string, w http.ResponseWriter, r *http.Request) {
	t, exists := p.targets[name]
	if !exists {
		http.Error(w, "Service not found", http.StatusNotFound)
		return
	}
	t.proxy.ServeHTTP(w, r)
}
