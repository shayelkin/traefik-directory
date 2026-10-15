package main

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const maxRuleDepth = 64

type node struct {
	op   byte // '&', '|', '!' or 'm' (matcher)
	kids []*node
	name string
	args []string
}

type parser struct {
	s     string
	i     int
	depth int
}

func parseRule(s string) (*node, error) {
	p := &parser{s: s}
	n, err := p.or()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, fmt.Errorf("unexpected %q at offset %d", p.s[p.i:], p.i)
	}
	return n, nil
}

func (p *parser) ws() {
	for p.i < len(p.s) && strings.IndexByte(" \t\r\n", p.s[p.i]) >= 0 {
		p.i++
	}
}

func (p *parser) peek(tok string) bool {
	p.ws()
	return strings.HasPrefix(p.s[p.i:], tok)
}

func (p *parser) or() (*node, error) {
	n, err := p.and()
	if err != nil {
		return nil, err
	}
	for p.peek("||") {
		p.i += 2
		r, err := p.and()
		if err != nil {
			return nil, err
		}
		n = &node{op: '|', kids: []*node{n, r}}
	}
	return n, nil
}

func (p *parser) and() (*node, error) {
	n, err := p.unary()
	if err != nil {
		return nil, err
	}
	for p.peek("&&") {
		p.i += 2
		r, err := p.unary()
		if err != nil {
			return nil, err
		}
		n = &node{op: '&', kids: []*node{n, r}}
	}
	return n, nil
}

func (p *parser) unary() (*node, error) {
	p.depth++
	defer func() { p.depth-- }()
	if p.depth > maxRuleDepth {
		return nil, fmt.Errorf("rule nested deeper than %d", maxRuleDepth)
	}
	if p.peek("!") {
		p.i++
		k, err := p.unary()
		if err != nil {
			return nil, err
		}
		return &node{op: '!', kids: []*node{k}}, nil
	}
	if p.peek("(") {
		p.i++
		n, err := p.or()
		if err != nil {
			return nil, err
		}
		if !p.peek(")") {
			return nil, fmt.Errorf("missing ) at offset %d", p.i)
		}
		p.i++
		return n, nil
	}
	return p.matcher()
}

func isIdent(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func (p *parser) matcher() (*node, error) {
	p.ws()
	start := p.i
	for p.i < len(p.s) && isIdent(p.s[p.i]) {
		p.i++
	}
	name := p.s[start:p.i]
	if name == "" {
		return nil, fmt.Errorf("expected matcher at offset %d", start)
	}
	if !p.peek("(") {
		return nil, fmt.Errorf("expected ( after %s", name)
	}
	p.i++
	var args []string
	for {
		arg, err := p.str()
		if err != nil {
			return nil, err
		}
		args = append(args, arg)
		if p.peek(",") {
			p.i++
			continue
		}
		if p.peek(")") {
			p.i++
			return &node{op: 'm', name: strings.ToLower(name), args: args}, nil
		}
		return nil, fmt.Errorf("expected , or ) at offset %d", p.i)
	}
}

func (p *parser) str() (string, error) {
	p.ws()
	if p.i >= len(p.s) {
		return "", fmt.Errorf("unexpected end of rule")
	}
	quote := p.s[p.i]
	p.i++
	switch quote {
	case '`':
		end := strings.IndexByte(p.s[p.i:], '`')
		if end < 0 {
			return "", fmt.Errorf("unterminated string")
		}
		out := p.s[p.i : p.i+end]
		p.i += end + 1
		return out, nil
	case '"':
		start := p.i - 1
		for p.i < len(p.s) {
			c := p.s[p.i]
			p.i++
			if c == '\\' {
				if p.i >= len(p.s) {
					return "", fmt.Errorf("unterminated string")
				}
				p.i++
				continue
			}
			if c == '"' {
				out, err := strconv.Unquote(p.s[start:p.i])
				if err != nil {
					return "", fmt.Errorf("invalid quoted string: %w", err)
				}
				return out, nil
			}
		}
		return "", fmt.Errorf("unterminated string")
	}
	return "", fmt.Errorf("expected quoted string at offset %d", p.i-1)
}

type ruleInfo struct {
	hosts       []string
	hostMatcher bool
	path        string
}

// analyze extracts the hosts and path a request must have to match the rule,
// applying negation like Traefik does (De Morgan) and picking the first viable
// alternative of every disjunction. Negated matchers contribute nothing.
func analyze(n *node, neg bool) ruleInfo {
	switch n.op {
	case '!':
		return analyze(n.kids[0], !neg)
	case 'm':
		if neg {
			return ruleInfo{}
		}
		return matcherInfo(n)
	}

	infos := make([]ruleInfo, len(n.kids))
	for i, k := range n.kids {
		infos[i] = analyze(k, neg)
	}

	if (n.op == '&') != neg {
		var out ruleInfo
		for _, in := range infos {
			if len(out.hosts) == 0 {
				out.hosts = in.hosts
			}
			if out.path == "" {
				out.path = in.path
			}
			out.hostMatcher = out.hostMatcher || in.hostMatcher
		}
		return out
	}

	for _, in := range infos {
		if len(in.hosts) > 0 {
			return in
		}
	}
	for _, in := range infos {
		if in.path != "" {
			return in
		}
	}
	return infos[0]
}

func matcherInfo(n *node) ruleInfo {
	switch n.name {
	case "host":
		out := ruleInfo{hostMatcher: true}
		for _, h := range n.args {
			if isConcreteHost(h) {
				out.hosts = append(out.hosts, h)
			}
		}
		return out
	case "hostregexp", "hostsni", "hostsniregexp":
		return ruleInfo{hostMatcher: true}
	case "path", "pathprefix":
		p := n.args[0]
		if strings.HasPrefix(p, "/") && !strings.ContainsAny(p, "{}") {
			return ruleInfo{path: p}
		}
	}
	return ruleInfo{}
}

func isConcreteHost(h string) bool {
	if strings.ContainsAny(h, "*{}") {
		return false
	}
	_, port, err := splitAuthority(h)
	return err == nil && port == ""
}

// splitAuthority validates a bare host or host:port, rejecting userinfo,
// paths, queries, fragments and malformed ports.
func splitAuthority(s string) (host, port string, err error) {
	u, err := url.Parse("http://" + s)
	if err != nil {
		return "", "", err
	}
	if u.User != nil || u.Host != s || u.Hostname() == "" || strings.HasSuffix(s, ":") {
		return "", "", fmt.Errorf("invalid host %q", s)
	}
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return "", "", fmt.Errorf("invalid port in %q", s)
		}
	}
	return u.Hostname(), u.Port(), nil
}

func joinHostPort(host, port string) string {
	if port != "" {
		return net.JoinHostPort(host, port)
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]"
	}
	return host
}
