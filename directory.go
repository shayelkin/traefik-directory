package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

const (
	apiTimeout = 10 * time.Second
	maxPages   = 100
	maxBody    = 8 << 20
)

type config struct {
	APIURL      string
	Listen      string
	EntryPoints []string
	DefaultHost string
}

func parseAPIURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "http://localhost:8080", nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("TRAEFIK_API_URL must be an http(s) URL without credentials, query or fragment, got %q", raw)
	}
	return strings.TrimRight(u.String(), "/"), nil
}

func configFromEnv(get func(string) string) (config, error) {
	apiURL, err := parseAPIURL(get("TRAEFIK_API_URL"))
	if err != nil {
		return config{}, err
	}
	cfg := config{
		APIURL:      apiURL,
		Listen:      get("LISTEN_ADDR"),
		DefaultHost: strings.TrimSpace(get("DEFAULT_HOST")),
	}
	if cfg.Listen == "" {
		cfg.Listen = ":8081"
	}
	for _, ep := range strings.Split(get("ENTRYPOINTS"), ",") {
		if ep = strings.TrimSpace(ep); ep != "" {
			cfg.EntryPoints = append(cfg.EntryPoints, ep)
		}
	}
	if cfg.DefaultHost != "" {
		if _, _, err := splitAuthority(cfg.DefaultHost); err != nil {
			return config{}, fmt.Errorf("DEFAULT_HOST must be a bare host (optionally host:port): %w", err)
		}
	}
	if len(cfg.EntryPoints) == 0 {
		return config{}, fmt.Errorf("ENTRYPOINTS must list at least one entrypoint name (comma separated)")
	}
	return cfg, nil
}

type router struct {
	Name        string          `json:"name"`
	Rule        string          `json:"rule"`
	Status      string          `json:"status"`
	EntryPoints []string        `json:"entryPoints"`
	TLS         json.RawMessage `json:"tls"`
}

func (r router) tls() bool {
	return len(r.TLS) > 0 && string(r.TLS) != "null"
}

type entryPoint struct {
	Name    string `json:"name"`
	Address string `json:"address"`
}

type tile struct {
	Title    string
	Subtitle string
	URL      string
}

func portOf(address string) string {
	address, _, _ = strings.Cut(address, "/")
	_, port, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return port
}

func schemeOf(r router) (scheme, defaultPort string) {
	if r.tls() {
		return "https", "443"
	}
	return "http", "80"
}

func routerURL(r router, epPort, defaultHost string) string {
	root, err := parseRule(r.Rule)
	if err != nil {
		return ""
	}
	info := analyze(root, false)

	authority := defaultHost
	switch {
	case len(info.hosts) > 0:
		authority = info.hosts[0]
	case info.hostMatcher || info.path == "":
		return ""
	}
	if authority == "" {
		return ""
	}
	host, port, err := splitAuthority(authority)
	if err != nil {
		return ""
	}

	scheme, defPort := schemeOf(r)
	if port == "" && epPort != "" && epPort != defPort {
		port = epPort
	}
	u := url.URL{Scheme: scheme, Host: joinHostPort(host, port), Path: info.path}
	return u.String()
}

func pickEntryPoint(r router, allow map[string]bool, ports map[string]string) (string, bool) {
	_, defPort := schemeOf(r)
	first, found := "", false
	for _, name := range r.EntryPoints {
		if !allow[name] {
			continue
		}
		if ports[name] == defPort {
			return name, true
		}
		if !found {
			first, found = name, true
		}
	}
	return first, found
}

func buildTiles(routers []router, eps []entryPoint, allowed []string, defaultHost string) []tile {
	allow := make(map[string]bool, len(allowed))
	for _, a := range allowed {
		allow[a] = true
	}
	ports := make(map[string]string, len(eps))
	for _, ep := range eps {
		ports[ep.Name] = portOf(ep.Address)
	}

	var tiles []tile
	for _, r := range routers {
		if r.Status == "disabled" {
			continue
		}
		name, ok := pickEntryPoint(r, allow, ports)
		if !ok {
			continue
		}
		t := tile{Title: strings.SplitN(r.Name, "@", 2)[0], Subtitle: r.Rule, URL: routerURL(r, ports[name], defaultHost)}
		if t.URL != "" {
			t.Subtitle = strings.TrimPrefix(strings.TrimPrefix(t.URL, "https://"), "http://")
		}
		if t.Title == "" {
			t.Title = cmpFallback(t.Subtitle, "(unnamed)")
		}
		tiles = append(tiles, t)
	}
	slices.SortStableFunc(tiles, func(a, b tile) int {
		return cmpChain(
			strings.Compare(strings.ToLower(a.Title), strings.ToLower(b.Title)),
			strings.Compare(a.Title, b.Title),
			strings.Compare(a.Subtitle, b.Subtitle),
			strings.Compare(a.URL, b.URL),
		)
	})
	return tiles
}

func cmpFallback(s, fallback string) string {
	if s == "" {
		return fallback
	}
	return s
}

func cmpChain(cs ...int) int {
	for _, c := range cs {
		if c != 0 {
			return c
		}
	}
	return 0
}

func fetchPage[T any](ctx context.Context, client *http.Client, base, path, pageNum string) ([]T, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+path+"?per_page=100&page="+pageNum, nil)
	if err != nil {
		return nil, "", err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("%s: unexpected status %s", path, resp.Status)
	}

	dec := json.NewDecoder(io.LimitReader(resp.Body, maxBody))
	var items []T
	if err := dec.Decode(&items); err != nil {
		return nil, "", fmt.Errorf("%s: %w", path, err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, "", fmt.Errorf("%s: unexpected data after JSON body", path)
	}
	return items, resp.Header.Get("X-Next-Page"), nil
}

func fetchAll[T any](ctx context.Context, client *http.Client, base, path string) ([]T, error) {
	var all []T
	pageNum := "1"
	for range maxPages {
		items, next, err := fetchPage[T](ctx, client, base, path, pageNum)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if next == "" || next == "1" {
			return all, nil
		}
		pageNum = next
	}
	return nil, fmt.Errorf("%s: more than %d pages", path, maxPages)
}

//go:embed templates/index.html
var indexSource string

var indexTmpl = template.Must(template.New("index").Parse(indexSource))

func newHandler(cfg config, client *http.Client) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), apiTimeout)
		defer cancel()

		var (
			routers      []router
			eps          []entryPoint
			rErr, epsErr error
			wg           sync.WaitGroup
		)
		wg.Add(2)
		go func() {
			defer wg.Done()
			routers, rErr = fetchAll[router](ctx, client, cfg.APIURL, "/api/http/routers")
		}()
		go func() {
			defer wg.Done()
			eps, epsErr = fetchAll[entryPoint](ctx, client, cfg.APIURL, "/api/entrypoints")
		}()
		wg.Wait()

		data := struct {
			Tiles []tile
			Err   string
		}{}
		status := http.StatusOK
		if err := errors.Join(rErr, epsErr); err != nil {
			log.Printf("traefik api: %v", err)
			data.Err = "Unable to query the Traefik API."
			status = http.StatusBadGateway
		} else {
			data.Tiles = buildTiles(routers, eps, cfg.EntryPoints, cfg.DefaultHost)
		}

		var buf bytes.Buffer
		if err := indexTmpl.Execute(&buf, data); err != nil {
			log.Printf("render: %v", err)
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write(buf.Bytes())
	})
	return mux
}
