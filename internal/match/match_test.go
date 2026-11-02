package match

import "testing"

func table() *Table[string] {
	return NewTable([]Entry[string]{
		{Prefix: "/api", Value: "gateway"},
		{Prefix: "/api/orders", Value: "orders"},
		{Prefix: "/api/dash", Exact: true, Value: "dash"},
		{Prefix: "/svc", Var: true, Allow: map[string]bool{"billing": true}, Value: "svc"},
	})
}

func TestLookup(t *testing.T) {
	cases := []struct {
		path, value, rest, service string
		found, blocked             bool
	}{
		{"/api", "gateway", "", "", true, false},
		{"/api/users/1", "gateway", "/users/1", "", true, false},
		{"/api/orders", "orders", "", "", true, false},
		{"/api/orders/7/lines", "orders", "/7/lines", "", true, false},
		{"/api/ordersfoo", "gateway", "/ordersfoo", "", true, false},
		{"/api/dash", "dash", "", "", true, false},
		{"/api/dash/x", "gateway", "/dash/x", "", true, false},
		{"/apifoo", "", "", "", false, false},
		{"/svc/billing", "svc", "", "billing", true, false},
		{"/svc/billing/x/y", "svc", "/x/y", "billing", true, false},
		{"/svc/vault/secrets", "", "", "", false, true},
		{"/svc", "", "", "", false, false},
		{"/other", "", "", "", false, false},
	}
	tbl := table()
	for _, c := range cases {
		r := tbl.Lookup(c.path)
		if r.Value != c.value || r.Rest != c.rest || r.Service != c.service || r.Found != c.found || r.Blocked != c.blocked {
			t.Errorf("Lookup(%q) = %+v", c.path, r)
		}
	}
}

func TestVarFallsThroughToCatchAll(t *testing.T) {
	tbl := NewTable([]Entry[string]{
		{Prefix: "/api", Value: "gateway"},
		{Prefix: "/api", Var: true, Allow: map[string]bool{"billing": true}, Value: "svc"},
	})
	if r := tbl.Lookup("/api/billing/x"); r.Value != "svc" {
		t.Errorf("allowed service = %+v", r)
	}
	if r := tbl.Lookup("/api/other"); r.Value != "gateway" || r.Blocked {
		t.Errorf("catch-all = %+v", r)
	}
}

func TestPattern(t *testing.T) {
	cases := []struct {
		method, pattern, reqMethod, rest string
		want                             bool
	}{
		{"GET", "/featured/**", "GET", "/featured", true},
		{"GET", "/featured/**", "GET", "/featured/a/b", true},
		{"GET", "/featured/**", "POST", "/featured/a", false},
		{"GET", "/featured/**", "GET", "/featuredx", false},
		{"", "/x", "POST", "/x", true},
		{"", "/x", "GET", "/x/y", false},
		{"", "/items/*/lines", "GET", "/items/9/lines", true},
		{"", "/items/*/lines", "GET", "/items/9/10/lines", false},
		{"", "/**", "GET", "/anything/at/all", true},
	}
	for _, c := range cases {
		if got := NewPattern(c.method, c.pattern).Match(c.reqMethod, c.rest); got != c.want {
			t.Errorf("%s %s vs %s %s = %v", c.method, c.pattern, c.reqMethod, c.rest, got)
		}
	}
}

func TestSafePath(t *testing.T) {
	good := []string{"/", "/api", "/api/x/", "/a%20b", "/a.b/c..d", "/%E2%9C%93", "/100%25"}
	bad := []string{
		"/api/../secret", "/api/./x", "/api//x", "/api/%2e%2e/secret", "/api/%2E%2E/secret",
		"/api/.%2e/secret", "/api/%252e%252e/secret", "/api/a%2fb", "/api/a%2Fb", "/api/a%252fb",
		"/api/a%5cb", "/api\\x", "/api/%00", "/api/%zz", "/api/%25252525252e",
	}
	for _, p := range good {
		if !SafePath(p) {
			t.Errorf("SafePath(%q) = false", p)
		}
	}
	for _, p := range bad {
		if SafePath(p) {
			t.Errorf("SafePath(%q) = true", p)
		}
	}
}
