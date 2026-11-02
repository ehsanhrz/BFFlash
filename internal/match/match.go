// Package match resolves request paths to declared prefixes and rules.
package match

import (
	"net/url"
	"sort"
	"strings"
)

// Entry is one declared path. A Var entry claims Prefix/{name}/... only for
// names in Allow. An Exact entry claims the path alone.
type Entry[T any] struct {
	Prefix string
	Exact  bool
	Var    bool
	Allow  map[string]bool
	Value  T
}

// Table is a longest-prefix-wins route table.
type Table[T any] struct {
	entries []Entry[T]
}

// NewTable orders entries so the most specific one is tried first.
func NewTable[T any](entries []Entry[T]) *Table[T] {
	sorted := append([]Entry[T](nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool {
		return specificity(sorted[i]) > specificity(sorted[j])
	})
	return &Table[T]{entries: sorted}
}

func specificity[T any](e Entry[T]) int {
	n := len(e.Prefix) * 2
	if e.Var {
		n++ // /api/{service} beats a plain /api
	}
	return n
}

// Result is a Lookup outcome.
type Result[T any] struct {
	Value   T
	Rest    string // path below the matched prefix, "" or starting with /
	Service string // the {name} value for a Var entry
	Found   bool
	Blocked bool // inside a Var entry's prefix, but not on its allow list
}

// Lookup finds the entry for a decoded path.
func (t *Table[T]) Lookup(path string) Result[T] {
	var res Result[T]
	for i := range t.entries {
		e := &t.entries[i]
		switch {
		case e.Exact:
			if path == e.Prefix {
				res.Value, res.Found, res.Blocked = e.Value, true, false
				return res
			}
		case e.Var:
			rest, ok := below(path, e.Prefix)
			if !ok || rest == "" {
				continue
			}
			name, tail, _ := strings.Cut(rest[1:], "/")
			if e.Allow[name] {
				res.Value, res.Service, res.Found, res.Blocked = e.Value, name, true, false
				if strings.Contains(rest[1:], "/") {
					res.Rest = "/" + tail
				}
				return res
			}
			res.Blocked = true
		default:
			if rest, ok := below(path, e.Prefix); ok {
				res.Value, res.Rest, res.Found, res.Blocked = e.Value, rest, true, false
				return res
			}
		}
	}
	return res
}

// below reports whether path is prefix or sits under it on a segment boundary,
// so /api/orders never matches /api/ordersfoo.
func below(path, prefix string) (string, bool) {
	if prefix == "/" {
		return path, true
	}
	if !strings.HasPrefix(path, prefix) {
		return "", false
	}
	rest := path[len(prefix):]
	if rest != "" && rest[0] != '/' {
		return "", false
	}
	return rest, true
}

// Pattern is a compiled rule match: an optional method plus path segments,
// where * is one segment and a trailing ** is any remainder, including none.
type Pattern struct {
	method string
	segs   []string
}

// NewPattern compiles a pattern already checked by config.ParseMatch.
func NewPattern(method, pattern string) Pattern {
	return Pattern{method: method, segs: strings.Split(strings.TrimPrefix(pattern, "/"), "/")}
}

// Match tests a method and a path relative to the API's prefix.
func (p Pattern) Match(method, rest string) bool {
	if p.method != "" && p.method != method {
		return false
	}
	path := strings.Split(strings.TrimPrefix(rest, "/"), "/")
	for i, seg := range p.segs {
		if seg == "**" {
			return true
		}
		if i >= len(path) {
			return false
		}
		if seg != "*" && seg != path[i] {
			return false
		}
	}
	return len(path) == len(p.segs)
}

// SafePath reports whether a raw request path is free of anything that could
// escape a target's base path. Catch-all prefixes forward arbitrary paths, so
// each layer of percent-encoding is inspected: an upstream that decodes twice
// must see nothing a single decode would have hidden.
func SafePath(raw string) bool {
	s := raw
	for i := range 4 {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "%2f") || strings.Contains(lower, "%5c") {
			return false
		}
		u, err := url.PathUnescape(s)
		if err != nil {
			// Only the raw path must be valid. Past that, a stray % is literal
			// text like /100%25, and the checks below already saw this layer.
			return i > 0
		}
		if strings.ContainsAny(u, "\\\x00") {
			return false
		}
		segs := strings.Split(u, "/")
		for i, seg := range segs {
			if seg == "." || seg == ".." {
				return false
			}
			if seg == "" && i != 0 && i != len(segs)-1 {
				return false
			}
		}
		if u == s {
			return true
		}
		s = u
	}
	return false // still encoded after four rounds: nothing legitimate does this
}
