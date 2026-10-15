package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"testing/quick"
)

var tlsOn = json.RawMessage(`{}`)

func TestRouterURL(t *testing.T) {
	cases := []struct {
		name, rule string
		tls        bool
		epPort     string
		def        string
		want       string
	}{
		{"backticks", "Host(`a.com`)", false, "80", "", "http://a.com"},
		{"double quotes", `Host("a.com")`, false, "80", "", "http://a.com"},
		{"escaped quotes", `Host("a.com") && PathPrefix("/q\"x")`, false, "80", "", "http://a.com/q%22x"},
		{"hex escape", `Host("a.com") && PathPrefix("/a\x2fb")`, false, "80", "", "http://a.com/a/b"},
		{"newline escape", `Host("a.com") && PathPrefix("/a\nb")`, false, "80", "", "http://a.com/a%0Ab"},
		{"invalid escape", `Host("a.com") && PathPrefix("/a\q")`, false, "80", "", ""},
		{"matcher case", "HOST(`a.com`)", false, "80", "", "http://a.com"},
		{"tls", "Host(`a.com`)", true, "443", "", "https://a.com"},
		{"non default port", "Host(`a.com`)", true, "8443", "", "https://a.com:8443"},
		{"multiple hosts", "Host(`a.com`, `b.com`)", false, "80", "", "http://a.com"},
		{"path", "Host(`a.com`) && PathPrefix(`/api`)", false, "80", "", "http://a.com/api"},
		{"path escaped", "Host(`a.com`) && PathPrefix(`/a b`)", false, "80", "", "http://a.com/a%20b"},
		{"negated path ignored", "Host(`a.com`) && !PathPrefix(`/admin`)", false, "80", "", "http://a.com"},
		{"negated host ignored", "!Host(`b.com`) && PathPrefix(`/x`)", false, "80", "home.lan", "http://home.lan/x"},
		{"negated host no default", "!Host(`b.com`) && PathPrefix(`/x`)", false, "80", "", ""},
		{"or picks first host", "Host(`a.com`) || PathPrefix(`/x`)", false, "80", "", "http://a.com"},
		{"or prefers host over earlier path", "PathPrefix(`/x`) || Host(`a.com`)", false, "80", "", "http://a.com"},
		{"negated or", "!(Host(`a.com`) || PathPrefix(`/x`))", false, "80", "home.lan", ""},
		{"negated and", "!(Host(`a.com`) && PathPrefix(`/x`))", false, "80", "home.lan", ""},
		{"double negation", "!!Host(`a.com`)", false, "80", "", "http://a.com"},
		{"parens", "(Host(`a.com`) || Host(`b.com`)) && PathPrefix(`/p`)", false, "80", "", "http://a.com/p"},
		{"v2 path pattern with host", "Host(`a.com`) && PathPrefix(`/api/{id:[0-9]+}`)", false, "80", "", "http://a.com"},
		{"v2 path pattern only", "PathPrefix(`/api/{id:[0-9]+}`)", false, "80", "home.lan", ""},
		{"relative path ignored", "PathPrefix(`x`)", false, "80", "home.lan", ""},
		{"wildcard host", "Host(`*.a.com`)", false, "80", "home.lan", ""},
		{"host regexp blocks default", "HostRegexp(`^a$`) && PathPrefix(`/x`)", false, "80", "home.lan", ""},
		{"path only default", "PathPrefix(`/grafana`)", true, "443", "home.lan", "https://home.lan/grafana"},
		{"path only default port", "PathPrefix(`/x`)", false, "8080", "home.lan", "http://home.lan:8080/x"},
		{"default with own port", "PathPrefix(`/x`)", false, "8080", "home.lan:9000", "http://home.lan:9000/x"},
		{"default ipv6", "PathPrefix(`/x`)", false, "8080", "[::1]", "http://[::1]:8080/x"},
		{"default ipv6 port", "PathPrefix(`/x`)", false, "8080", "[::1]:9", "http://[::1]:9/x"},
		{"path only no default", "PathPrefix(`/x`)", false, "80", "", ""},
		{"no host no path", "Method(`GET`)", false, "80", "home.lan", ""},
		{"userinfo host", "Host(`x@evil.com`)", false, "80", "", ""},
		{"host with path", "Host(`a.com/x`)", false, "80", "", ""},
		{"host with query", "Host(`a.com?x`)", false, "80", "", ""},
		{"host with port", "Host(`a.com:99`)", false, "80", "", ""},
		{"host with space", "Host(`a b.com`)", false, "80", "", ""},
		{"unterminated", "Host(`a.com", false, "80", "", ""},
		{"unterminated quote", `Host("a.com`, false, "80", "", ""},
		{"open paren", "Host(`a.com`", false, "80", "", ""},
		{"trailing garbage", "Host(`a.com`) &&", false, "80", "", ""},
		{"empty args", "Host()", false, "80", "", ""},
		{"empty", "", false, "80", "", ""},
		{"deep nesting", strings.Repeat("(", 100000) + "Host(`a.com`)" + strings.Repeat(")", 100000), false, "80", "", ""},
		{"deep negation", strings.Repeat("!", 100000) + "Host(`a.com`)", false, "80", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := router{Rule: c.rule}
			if c.tls {
				r.TLS = tlsOn
			}
			if got := routerURL(r, c.epPort, c.def); got != c.want {
				t.Errorf("got %q want %q", got, c.want)
			}
		})
	}
}

func TestPortOf(t *testing.T) {
	for in, want := range map[string]string{
		":443":          "443",
		":443/tcp":      "443",
		"0.0.0.0:80":    "80",
		"[::]:8080/tcp": "8080",
		":53/udp":       "53",
		"garbage":       "",
		"":              "",
	} {
		if got := portOf(in); got != want {
			t.Errorf("portOf(%q) = %q want %q", in, got, want)
		}
	}
}

func TestBuildTiles(t *testing.T) {
	routers := []router{
		{Name: "a@docker", Rule: "Host(`a.com`)", Status: "enabled", EntryPoints: []string{"websecure"}, TLS: tlsOn},
		{Name: "b@docker", Rule: "Host(`b.com`)", Status: "enabled", EntryPoints: []string{"web"}, TLS: json.RawMessage(`null`)},
		{Name: "c", Rule: "Host(`c.com`)", Status: "enabled", EntryPoints: []string{"internal"}},
		{Name: "d", Rule: "Host(`d.com`)", Status: "disabled", EntryPoints: []string{"web"}},
		{Name: "e", Rule: "Host(`e.com`)", Status: "enabled", EntryPoints: []string{"alt"}, TLS: tlsOn},
		{Name: "a-api", Rule: "Host(`a.com`) && PathPrefix(`/api`)", Status: "enabled", EntryPoints: []string{"websecure", "web"}, TLS: tlsOn},
		{Name: "g", Rule: "PathPrefix(`/x`)", Status: "enabled", EntryPoints: []string{"web"}},
		{Name: "h", Rule: "Host(`*.wild`)", Status: "enabled", EntryPoints: []string{"web"}},
		{Name: "w@file", Rule: "Host(`w.com`)", Status: "warning", EntryPoints: []string{"web"}},
		{Name: "", Rule: "Host(`anon.com`)", EntryPoints: []string{"web"}},
		{Name: "@file", Rule: "", EntryPoints: []string{"web"}},
	}
	eps := []entryPoint{{"web", ":80"}, {"websecure", ":443"}, {"internal", ":9000"}, {"alt", ":8443"}}

	got := buildTiles(routers, eps, []string{"web", "websecure", "alt"}, "")
	want := []tile{
		{"(unnamed)", "", ""},
		{"a", "a.com", "https://a.com"},
		{"a-api", "a.com/api", "https://a.com/api"},
		{"b", "b.com", "http://b.com"},
		{"e", "e.com:8443", "https://e.com:8443"},
		{"g", "PathPrefix(`/x`)", ""},
		{"h", "Host(`*.wild`)", ""},
		{"anon.com", "anon.com", "http://anon.com"},
		{"w", "w.com", "http://w.com"},
	}
	slices.SortFunc(want, compareTiles)
	if !slices.Equal(got, want) {
		t.Fatalf("got  %v\nwant %v", got, want)
	}
}

func TestBuildTilesTieBreak(t *testing.T) {
	mk := func(names ...string) []router {
		var rs []router
		for _, n := range names {
			rs = append(rs, router{Name: n, Rule: "Host(`x.com`)", EntryPoints: []string{"web"}})
		}
		return rs
	}
	eps := []entryPoint{{"web", ":80"}}
	a := buildTiles(mk("A", "a"), eps, []string{"web"}, "")
	b := buildTiles(mk("a", "A"), eps, []string{"web"}, "")
	if !slices.Equal(a, b) || a[0].Title != "A" {
		t.Errorf("order not deterministic: %v vs %v", a, b)
	}
}

func TestEntryPointChoiceIsOrderIndependent(t *testing.T) {
	eps := []entryPoint{{"web", ":80/tcp"}, {"websecure", ":443/tcp"}, {"alt", ":8443"}}
	allowed := []string{"web", "websecure", "alt"}
	cases := []struct {
		name string
		tls  json.RawMessage
		eps  []string
		want string
	}{
		{"tls prefers 443", tlsOn, []string{"web", "websecure"}, "https://a.com"},
		{"tls prefers 443 reversed", tlsOn, []string{"websecure", "web"}, "https://a.com"},
		{"plain prefers 80", nil, []string{"websecure", "web"}, "http://a.com"},
		{"plain prefers 80 reversed", nil, []string{"web", "websecure"}, "http://a.com"},
		{"no default falls back to first", tlsOn, []string{"alt", "web"}, "https://a.com:8443"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := buildTiles([]router{{Name: "a", Rule: "Host(`a.com`)", TLS: c.tls, EntryPoints: c.eps}}, eps, allowed, "")
			if len(got) != 1 || got[0].URL != c.want {
				t.Errorf("got %v want %s", got, c.want)
			}
		})
	}
}

func compareTiles(a, b tile) int {
	return cmpChain(
		strings.Compare(strings.ToLower(a.Title), strings.ToLower(b.Title)),
		strings.Compare(a.Title, b.Title),
		strings.Compare(a.Subtitle, b.Subtitle),
		strings.Compare(a.URL, b.URL),
	)
}

var (
	genHosts   = []string{"a.com", "b.org", "sub.c.net", "*.wild.io", "x@evil.com", "bad host", "d.com:81", "1.2.3.4", "[::1]"}
	genPaths   = []string{"/", "/api", "/a b", "/x/{id}", "rel", "/q?z"}
	genEPs     = []string{"web", "websecure", "internal", "alt"}
	genStatus  = []string{"", "enabled", "disabled", "warning"}
	genDefault = []string{"", "home.lan", "home.lan:9000", "[::1]"}
)

func genRule(rng *rand.Rand, depth int) string {
	pick := func(s []string) string { return s[rng.Intn(len(s))] }
	if depth == 0 || rng.Intn(4) == 0 {
		switch rng.Intn(6) {
		case 0:
			return "Host(`" + pick(genHosts) + "`)"
		case 1:
			return `Host("` + pick(genHosts) + `")`
		case 2:
			return "PathPrefix(`" + pick(genPaths) + "`)"
		case 3:
			return "HostRegexp(`^.+$`)"
		case 4:
			return "Method(`GET`)"
		}
		return pick([]string{"Host(", "&&", "((", "`", "!"})
	}
	switch rng.Intn(4) {
	case 0:
		return "!" + genRule(rng, depth-1)
	case 1:
		return "(" + genRule(rng, depth-1) + ")"
	case 2:
		return genRule(rng, depth-1) + " && " + genRule(rng, depth-1)
	}
	return genRule(rng, depth-1) + " || " + genRule(rng, depth-1)
}

func genRouters(rng *rand.Rand) ([]router, []entryPoint, []string, string) {
	routers := make([]router, rng.Intn(12))
	for i := range routers {
		r := router{Name: fmt.Sprintf("r%d@file", i), Rule: genRule(rng, 3), Status: genStatus[rng.Intn(len(genStatus))]}
		if rng.Intn(2) == 0 {
			r.TLS = tlsOn
		}
		for _, e := range genEPs {
			if rng.Intn(2) == 0 {
				r.EntryPoints = append(r.EntryPoints, e)
			}
		}
		routers[i] = r
	}
	eps := []entryPoint{{"web", ":80/tcp"}, {"websecure", ":443"}, {"internal", ":9000"}, {"alt", ":8443"}}
	var allowed []string
	for _, e := range genEPs {
		if rng.Intn(2) == 0 {
			allowed = append(allowed, e)
		}
	}
	return routers, eps, allowed, genDefault[rng.Intn(len(genDefault))]
}

func TestBuildTilesProperties(t *testing.T) {
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		routers, eps, allowed, def := genRouters(rng)
		tiles := buildTiles(routers, eps, allowed, def)

		byName := map[string]router{}
		want := 0
		for _, r := range routers {
			byName[strings.SplitN(r.Name, "@", 2)[0]] = r
			if r.Status == "disabled" {
				continue
			}
			for _, e := range r.EntryPoints {
				if slices.Contains(allowed, e) {
					want++
					break
				}
			}
		}
		if len(tiles) != want {
			t.Logf("seed %d: %d tiles want %d", seed, len(tiles), want)
			return false
		}
		if !slices.IsSortedFunc(tiles, compareTiles) {
			t.Logf("seed %d: not sorted", seed)
			return false
		}

		rev := slices.Clone(routers)
		slices.Reverse(rev)
		if !slices.Equal(tiles, buildTiles(rev, eps, allowed, def)) {
			t.Logf("seed %d: depends on input order", seed)
			return false
		}

		for _, tl := range tiles {
			r, ok := byName[tl.Title]
			if !ok || r.Status == "disabled" {
				t.Logf("seed %d: tile %v from unknown/disabled router", seed, tl)
				return false
			}
			if tl.URL == "" {
				continue
			}
			u, err := url.Parse(tl.URL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				t.Logf("seed %d: bad link %q", seed, tl.URL)
				return false
			}
			if (u.Scheme == "https") != r.tls() {
				t.Logf("seed %d: scheme mismatch %q", seed, tl.URL)
				return false
			}
			defHost, _, _ := splitAuthority(def)
			if !strings.Contains(r.Rule, u.Hostname()) && u.Hostname() != defHost {
				t.Logf("seed %d: host %q not in rule %q", seed, u.Hostname(), r.Rule)
				return false
			}
		}
		return true
	}
	if err := quick.Check(f, &quick.Config{MaxCount: 2000}); err != nil {
		t.Fatal(err)
	}
}

func TestConfigFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	base := func(k, v string) map[string]string { return map[string]string{"ENTRYPOINTS": "web", k: v} }

	if _, err := configFromEnv(env(nil)); err == nil {
		t.Error("expected error for missing ENTRYPOINTS")
	}
	if _, err := configFromEnv(env(map[string]string{"ENTRYPOINTS": " , "})); err == nil {
		t.Error("expected error for blank ENTRYPOINTS")
	}
	cfg, err := configFromEnv(env(map[string]string{"ENTRYPOINTS": "web, websecure", "TRAEFIK_API_URL": " http://t:8080/ "}))
	if err != nil || cfg.APIURL != "http://t:8080" || len(cfg.EntryPoints) != 2 || cfg.Listen != ":8081" {
		t.Errorf("unexpected: %+v %v", cfg, err)
	}

	for _, bad := range []string{"localhost:8080 ", "localhost:8080", "ftp://x", "http://u:p@x", "http://", "http://x?y=1", "http://x#f", "://"} {
		if _, err := configFromEnv(env(base("TRAEFIK_API_URL", bad))); err == nil {
			t.Errorf("expected error for TRAEFIK_API_URL=%q", bad)
		}
	}
	for _, bad := range []string{"http://x", "x/y", "a b", "x@evil.com", "a?b", "a#b", "host:notaport", "::1", "a.com:", "a.com:0", "a.com:70000", `a\b`} {
		if _, err := configFromEnv(env(base("DEFAULT_HOST", bad))); err == nil {
			t.Errorf("expected error for DEFAULT_HOST=%q", bad)
		}
	}
	for _, good := range []string{"home.lan", "home.lan:8080", "[::1]", "[::1]:8080", "10.0.0.1", " home.lan "} {
		if _, err := configFromEnv(env(base("DEFAULT_HOST", good))); err != nil {
			t.Errorf("DEFAULT_HOST=%q: %v", good, err)
		}
	}
}

func routersHandler(t *testing.T, routers func(w http.ResponseWriter, page string)) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/http/routers":
			routers(w, r.URL.Query().Get("page"))
		case "/api/entrypoints":
			w.Header().Set("X-Next-Page", "1")
			_, _ = w.Write([]byte(`[{"name":"web","address":":80"}]`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestFetchAllErrors(t *testing.T) {
	var requests atomic.Int32
	cases := map[string]func(w http.ResponseWriter, page string){
		"status":        func(w http.ResponseWriter, _ string) { http.Error(w, "nope", http.StatusInternalServerError) },
		"bad json":      func(w http.ResponseWriter, _ string) { _, _ = w.Write([]byte(`{not json`)) },
		"wrong type":    func(w http.ResponseWriter, _ string) { _, _ = w.Write([]byte(`{"a":1}`)) },
		"trailing data": func(w http.ResponseWriter, _ string) { _, _ = w.Write([]byte(`[] []`)) },
		"oversized": func(w http.ResponseWriter, _ string) {
			_, _ = w.Write([]byte("["))
			chunk := strings.Repeat(`{"name":"x"},`, 1000)
			for range (maxBody / len(chunk)) + 2 {
				_, _ = io.WriteString(w, chunk)
			}
			_, _ = w.Write([]byte(`{}]`))
		},
		"page cycle": func(w http.ResponseWriter, page string) {
			next := map[string]string{"1": "2", "2": "3", "3": "2"}[page]
			w.Header().Set("X-Next-Page", next)
			_, _ = w.Write([]byte(`[]`))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			requests.Store(0)
			srv := routersHandler(t, func(w http.ResponseWriter, page string) {
				requests.Add(1)
				h(w, page)
			})
			if _, err := fetchAll[router](t.Context(), srv.Client(), srv.URL, "/api/http/routers"); err == nil {
				t.Fatal("expected error")
			}
			if n := requests.Load(); n > maxPages {
				t.Errorf("made %d requests, limit is %d", n, maxPages)
			}
		})
	}
}

func TestFetchAllPaginates(t *testing.T) {
	srv := routersHandler(t, func(w http.ResponseWriter, page string) {
		n, _ := strconv.Atoi(page)
		if n < 3 {
			w.Header().Set("X-Next-Page", strconv.Itoa(n+1))
		} else {
			w.Header().Set("X-Next-Page", "1")
		}
		fmt.Fprintf(w, `[{"name":"p%d"}]`, n)
	})
	got, err := fetchAll[router](t.Context(), srv.Client(), srv.URL, "/api/http/routers")
	if err != nil || len(got) != 3 || got[2].Name != "p3" {
		t.Errorf("got %v, %v", got, err)
	}
}

func twoPageTraefik(t *testing.T) *httptest.Server {
	return routersHandler(t, func(w http.ResponseWriter, page string) {
		if page == "1" {
			w.Header().Set("X-Next-Page", "2")
			_, _ = w.Write([]byte(`[{"name":"first@docker","rule":"Host(` + "`a.com`" + `)","status":"enabled","entryPoints":["web"]}]`))
			return
		}
		w.Header().Set("X-Next-Page", "1")
		_, _ = w.Write([]byte(`[{"name":"evil<script>@docker","rule":"Host(` + "`<b>.com`" + `)","status":"enabled","entryPoints":["web"]}]`))
	})
}

func TestHandler(t *testing.T) {
	up := twoPageTraefik(t)
	front := httptest.NewServer(newHandler(config{APIURL: up.URL, EntryPoints: []string{"web"}}, up.Client()))
	defer front.Close()

	resp, err := http.Get(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	body := string(b)

	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("unexpected %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	for _, want := range []string{`href="http://a.com"`, "first", "evil&lt;script&gt;", "&lt;b&gt;.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("body missing %q:\n%s", want, body)
		}
	}
	for _, bad := range []string{"<b>.com", "<script>"} {
		if strings.Contains(body, bad) {
			t.Errorf("unescaped %q in body", bad)
		}
	}

	head, err := http.Head(front.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	head.Body.Close()
	if head.StatusCode != 200 {
		t.Errorf("HEAD: %d", head.StatusCode)
	}

	post, err := http.Post(front.URL+"/", "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	post.Body.Close()
	if post.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", post.StatusCode)
	}

	nf, err := http.Get(front.URL + "/nope")
	if err != nil {
		t.Fatal(err)
	}
	nf.Body.Close()
	if nf.StatusCode != 404 {
		t.Errorf("/nope: %d", nf.StatusCode)
	}
}

func TestHandlerUpstreamDown(t *testing.T) {
	up := twoPageTraefik(t)
	url, client := up.URL, up.Client()
	up.Close()
	h := newHandler(config{APIURL: url, EntryPoints: []string{"web"}}, client)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("got %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "text/html; charset=utf-8" {
		t.Errorf("content type %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "Unable to query the Traefik API.") {
		t.Errorf("missing error message: %s", rec.Body.String())
	}
}

func TestHandlerUpstreamBadStatus(t *testing.T) {
	up := routersHandler(t, func(w http.ResponseWriter, _ string) { http.Error(w, "boom", 500) })
	h := newHandler(config{APIURL: up.URL, EntryPoints: []string{"web"}}, up.Client())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusBadGateway {
		t.Errorf("got %d", rec.Code)
	}
}

func TestHandlerRenderErrorIsNotPartial(t *testing.T) {
	orig := indexTmpl
	t.Cleanup(func() { indexTmpl = orig })
	indexTmpl = template.Must(template.New("x").Parse("partial {{.Missing.Field}}"))

	up := twoPageTraefik(t)
	h := newHandler(config{APIURL: up.URL, EntryPoints: []string{"web"}}, up.Client())
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "partial") {
		t.Errorf("got %d %q", rec.Code, rec.Body.String())
	}
}
