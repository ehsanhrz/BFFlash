package config

import (
	"strings"
	"testing"
	"time"
)

const minimal = `
oidc:
  issuer: https://idp.example.com
  client_id: bfflash
  client_secret: ${OIDC_CLIENT_SECRET}

frontend:
  url: http://web:3000

apis:
  - path: /api
    to: http://gateway:8080
`

func TestMinimalConfig(t *testing.T) {
	t.Setenv("OIDC_CLIENT_SECRET", "s3cret")
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.OIDC.ClientSecret != "s3cret" {
		t.Errorf("secret = %q", c.OIDC.ClientSecret)
	}
	if c.Server.Listen != ":8080" || c.Server.BasePath != "/bff" || c.Server.CSRFHeader != "X-CSRF" {
		t.Errorf("server defaults = %+v", c.Server)
	}
	if e := Builtin().Apply(c.Defaults).Apply(c.APIs[0].Policy); e.Token != TokenUser {
		t.Errorf("default token = %q, want user", e.Token)
	}
}

func TestMissingEnvIsAnError(t *testing.T) {
	_, err := Parse([]byte(minimal))
	if err == nil || !strings.Contains(err.Error(), "OIDC_CLIENT_SECRET") {
		t.Fatalf("err = %v", err)
	}
}

func TestEnvValueCannotAddStructure(t *testing.T) {
	t.Setenv("OIDC_CLIENT_SECRET", "x\nserver:\n  listen: ':1'")
	c, err := Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	if c.Server.Listen != ":8080" {
		t.Errorf("listen = %q, env value changed structure", c.Server.Listen)
	}
}

func TestCascade(t *testing.T) {
	c, err := Parse([]byte(`
defaults:
  timeout: 10s
  retries: 1
  token: none
apis:
  - path: /a
    to: http://a
    timeout: 5s
    rules:
      - match: GET /x/**
        cache: 30s
        retries: 3
`))
	if err != nil {
		t.Fatal(err)
	}
	a := c.APIs[0]
	api := Builtin().Apply(c.Defaults).Apply(a.Policy)
	rule := api.Apply(a.Rules[0].Policy)
	if api.Timeout != 5*time.Second || api.Retries != 1 || api.Cache != 0 {
		t.Errorf("api = %+v", api)
	}
	if rule.Timeout != 5*time.Second || rule.Retries != 3 || rule.Cache != 30*time.Second {
		t.Errorf("rule = %+v", rule)
	}
}

func TestRateLimit(t *testing.T) {
	c, err := Parse([]byte(`
defaults:
  token: none
  rate_limit: 120/m per ip
apis:
  - path: /a
    to: http://a
    rate_limit: "off"
`))
	if err != nil {
		t.Fatal(err)
	}
	d := Builtin().Apply(c.Defaults)
	if d.RateLimit.Rate != 2 || d.RateLimit.Per != PerIP {
		t.Errorf("rate = %+v", d.RateLimit)
	}
	if off := d.Apply(c.APIs[0].Policy); off.RateLimit.Rate != 0 {
		t.Errorf("off rate = %+v", off.RateLimit)
	}
}

func TestComposeRefsAreNotEnvExpanded(t *testing.T) {
	c, err := Parse([]byte(`
defaults: { token: none }
compose:
  - path: /d
    steps:
      - { id: me, get: "/a?x=${steps.me.body.id}" }
    respond: "{}"
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := c.Compose[0].Steps[0].Get; !strings.Contains(got, "${steps.me.body.id}") {
		t.Errorf("get = %q", got)
	}
}

func TestRejected(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"unknown key", "defaults: { token: none }\napis: [{path: /a, to: 'http://a', nope: 1}]", "nope"},
		{"no apis", "defaults: { token: none }", "at least one"},
		{"token needs oidc", "apis: [{path: /a, to: 'http://a'}]", "oidc"},
		{"bad token", "defaults: { token: nope }\napis: [{path: /a, to: 'http://a'}]", "unknown token"},
		{"duplicate path", "defaults: { token: none }\napis: [{path: /a, to: 'http://a'}, {path: /a, to: 'http://b'}]", "twice"},
		{"trailing slash", "defaults: { token: none }\napis: [{path: /a/, to: 'http://a'}]", "not end"},
		{"management collision", "defaults: { token: none }\napis: [{path: /bff/x, to: 'http://a'}]", "management"},
		{"relative to", "defaults: { token: none }\napis: [{path: /a, to: 'a:80'}]", "absolute"},
		{"service without allow", "defaults: { token: none }\napis: [{path: '/a/{s}', to: 'http://{s}.svc'}]", "allow"},
		{"service empty allow", "defaults: { token: none }\napis: [{path: '/a/{s}', to: 'http://{s}.svc', allow: []}]", "allow"},
		{"service glob in allow", "defaults: { token: none }\napis: [{path: '/a/{s}', to: 'http://{s}.svc', allow: ['*']}]", "valid service"},
		{"placeholder not last", "defaults: { token: none }\napis: [{path: '/{s}/a', to: 'http://{s}.svc', allow: [x]}]", "last path segment"},
		{"allow without placeholder", "defaults: { token: none }\napis: [{path: /a, to: 'http://a', allow: [x]}]", "placeholder"},
		{"bad rule", "defaults: { token: none }\napis: [{path: /a, to: 'http://a', rules: [{match: 'GET x'}]}]", "must start"},
		{"glob mid path", "defaults: { token: none }\napis: [{path: /a, to: 'http://a', rules: [{match: '/**/x'}]}]", "last segment"},
		{"redis without key", "defaults: { token: none }\nsession: { store: redis, url: 'redis://r' }\napis: [{path: /a, to: 'http://a'}]", "encryption_key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.yaml))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
