// Package config loads and validates bfflash.yaml.
package config

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Token modes.
const (
	TokenUser         = "user"
	TokenClient       = "client"
	TokenUserOrClient = "user_or_client"
	TokenUserOrNone   = "user_or_none"
	TokenNone         = "none"
)

const (
	PerSession = "session"
	PerIP      = "ip"
)

type Config struct {
	Server   Server    `yaml:"server"`
	OIDC     *OIDC     `yaml:"oidc"`
	Session  Session   `yaml:"session"`
	Frontend Frontend  `yaml:"frontend"`
	Defaults Policy    `yaml:"defaults"`
	APIs     []API     `yaml:"apis"`
	Compose  []Compose `yaml:"compose"`
}

type Server struct {
	Listen       string `yaml:"listen"`
	PublicURL    string `yaml:"public_url"`
	BasePath     string `yaml:"base_path"`
	CSRFHeader   string `yaml:"csrf_header"`
	MaxBodyBytes int64  `yaml:"max_body_bytes"`
}

type OIDC struct {
	Issuer       string   `yaml:"issuer"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`
	ClientScopes []string `yaml:"client_scopes"` // for token: client
}

type Session struct {
	Store         string   `yaml:"store"`
	URL           string   `yaml:"url"`
	EncryptionKey string   `yaml:"encryption_key"`
	IdleTTL       Duration `yaml:"idle_ttl"`
	AbsoluteTTL   Duration `yaml:"absolute_ttl"`
}

type Frontend struct {
	URL string `yaml:"url"`
	Dir string `yaml:"dir"`
}

// Policy holds the settings that cascade from built-in defaults through
// defaults:, then each API, then each rule. A nil field inherits.
type Policy struct {
	Token     *string    `yaml:"token"`
	Timeout   *Duration  `yaml:"timeout"`
	Retries   *int       `yaml:"retries"`
	RateLimit *RateLimit `yaml:"rate_limit"`
	Cache     *Duration  `yaml:"cache"`
}

type API struct {
	Path   string   `yaml:"path"`
	To     string   `yaml:"to"`
	Allow  []string `yaml:"allow"`
	Rules  []Rule   `yaml:"rules"`
	Policy `yaml:",inline"`
}

type Rule struct {
	Match  string `yaml:"match"`
	Policy `yaml:",inline"`
}

type Compose struct {
	Path    string `yaml:"path"`
	Steps   []Step `yaml:"steps"`
	Respond string `yaml:"respond"`
	Policy  `yaml:",inline"`
}

type Step struct {
	ID       string `yaml:"id"`
	Get      string `yaml:"get"`
	Optional bool   `yaml:"optional"`
}

// Duration decodes strings like "30s".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	v, err := time.ParseDuration(n.Value)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q", n.Line, n.Value)
	}
	*d = Duration(v)
	return nil
}

// RateLimit decodes strings like "100/s per session". A zero value disables
// limiting, written as "off".
type RateLimit struct {
	Rate  float64
	Per   string
	Burst int
}

var rateRE = regexp.MustCompile(`^(\d+(?:\.\d+)?)/(s|m|h)(?:\s+per\s+(session|ip))?$`)

func (r *RateLimit) UnmarshalYAML(n *yaml.Node) error {
	if n.Value == "off" {
		*r = RateLimit{}
		return nil
	}
	m := rateRE.FindStringSubmatch(strings.TrimSpace(n.Value))
	if m == nil {
		return fmt.Errorf(`line %d: invalid rate_limit %q, want like "100/s per session"`, n.Line, n.Value)
	}
	v, _ := strconv.ParseFloat(m[1], 64)
	switch m[2] {
	case "m":
		v /= 60
	case "h":
		v /= 3600
	}
	per := m[3]
	if per == "" {
		per = PerSession
	}
	burst := int(v * 2)
	if burst < 1 {
		burst = 1
	}
	*r = RateLimit{Rate: v, Per: per, Burst: burst}
	return nil
}

// Load reads, expands, decodes and validates a config file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(raw)
}

// Parse is Load without the file read.
func Parse(raw []byte) (*Config, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	if err := expandEnv(&doc); err != nil {
		return nil, err
	}
	// Expansion works on decoded scalars, so a value from the environment can
	// never add YAML structure. Re-encoding lets the strict decoder run after it.
	expanded, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(expanded))
	dec.KnownFields(true)
	c := &Config{}
	if err := dec.Decode(c); err != nil {
		return nil, err
	}
	c.applyDefaults()
	if err := c.validate(); err != nil {
		return nil, err
	}
	return c, nil
}

// Only upper-case names expand, which leaves ${steps.me.body.id} for compose.
var envRE = regexp.MustCompile(`\$\{([A-Z_][A-Z0-9_]*)\}`)

func expandEnv(n *yaml.Node) error {
	if n.Kind == yaml.ScalarNode {
		var missing string
		n.Value = envRE.ReplaceAllStringFunc(n.Value, func(s string) string {
			name := envRE.FindStringSubmatch(s)[1]
			v, ok := os.LookupEnv(name)
			if !ok {
				missing = name
			}
			return v
		})
		if missing != "" {
			return fmt.Errorf("line %d: environment variable %s is not set", n.Line, missing)
		}
	}
	for _, c := range n.Content {
		if err := expandEnv(c); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) applyDefaults() {
	s := &c.Server
	if s.Listen == "" {
		s.Listen = ":8080"
	}
	if s.BasePath == "" {
		s.BasePath = "/bff"
	}
	if s.CSRFHeader == "" {
		s.CSRFHeader = "X-CSRF"
	}
	if s.MaxBodyBytes == 0 {
		s.MaxBodyBytes = 10 << 20
	}
	if c.OIDC != nil && len(c.OIDC.Scopes) == 0 {
		c.OIDC.Scopes = []string{"openid", "profile", "email", "offline_access"}
	}
	if c.Session.Store == "" {
		c.Session.Store = "memory"
	}
	if c.Session.IdleTTL == 0 {
		c.Session.IdleTTL = Duration(30 * time.Minute)
	}
	if c.Session.AbsoluteTTL == 0 {
		c.Session.AbsoluteTTL = Duration(12 * time.Hour)
	}
}

// Effective is a Policy with every field resolved.
type Effective struct {
	Token     string
	Timeout   time.Duration
	Retries   int
	RateLimit RateLimit
	Cache     time.Duration
}

// Builtin is the secure default every API starts from.
func Builtin() Effective {
	return Effective{Token: TokenUser, Timeout: 30 * time.Second}
}

// Apply returns e with the fields set in p replaced.
func (e Effective) Apply(p Policy) Effective {
	if p.Token != nil {
		e.Token = *p.Token
	}
	if p.Timeout != nil {
		e.Timeout = time.Duration(*p.Timeout)
	}
	if p.Retries != nil {
		e.Retries = *p.Retries
	}
	if p.RateLimit != nil {
		e.RateLimit = *p.RateLimit
	}
	if p.Cache != nil {
		e.Cache = time.Duration(*p.Cache)
	}
	return e
}

func (c *Config) validate() error {
	if len(c.APIs) == 0 && len(c.Compose) == 0 {
		return fmt.Errorf("apis: at least one API is required")
	}
	if !strings.HasPrefix(c.Server.BasePath, "/") || strings.HasSuffix(c.Server.BasePath, "/") {
		return fmt.Errorf("server.base_path: %q must start with / and not end with /", c.Server.BasePath)
	}
	if c.Server.PublicURL != "" {
		if err := checkURL(c.Server.PublicURL); err != nil {
			return fmt.Errorf("server.public_url: %w", err)
		}
	}
	if c.Frontend.URL != "" && c.Frontend.Dir != "" {
		return fmt.Errorf("frontend: set url or dir, not both")
	}
	if c.Frontend.URL != "" {
		if err := checkURL(c.Frontend.URL); err != nil {
			return fmt.Errorf("frontend.url: %w", err)
		}
	}
	if c.OIDC != nil {
		if c.OIDC.Issuer == "" || c.OIDC.ClientID == "" {
			return fmt.Errorf("oidc: issuer and client_id are required")
		}
	}
	if k := c.Session.EncryptionKey; k != "" && len(k) < 32 {
		return fmt.Errorf("session.encryption_key must be at least 32 characters")
	}
	switch c.Session.Store {
	case "memory":
	case "redis":
		if c.Session.URL == "" {
			return fmt.Errorf("session.url is required for the redis store")
		}
		if c.Session.EncryptionKey == "" {
			return fmt.Errorf("session.encryption_key is required for the redis store")
		}
	default:
		return fmt.Errorf("session.store: unknown store %q", c.Session.Store)
	}

	base := Builtin().Apply(c.Defaults)
	if err := c.checkPolicy("defaults", base); err != nil {
		return err
	}
	seen := map[string]bool{}
	claim := func(path string) error {
		if !strings.HasPrefix(path, "/") || (len(path) > 1 && strings.HasSuffix(path, "/")) {
			return fmt.Errorf("path %q must start with / and not end with /", path)
		}
		if path == c.Server.BasePath || strings.HasPrefix(path, c.Server.BasePath+"/") {
			return fmt.Errorf("path %q collides with the management endpoints at %s", path, c.Server.BasePath)
		}
		if path == "/healthz" || path == "/readyz" {
			return fmt.Errorf("path %q is reserved for health checks", path)
		}
		if seen[path] {
			return fmt.Errorf("path %q is declared twice", path)
		}
		seen[path] = true
		return nil
	}
	for i := range c.APIs {
		a := &c.APIs[i]
		if err := claim(a.Path); err != nil {
			return fmt.Errorf("apis[%d]: %w", i, err)
		}
		if err := a.validate(); err != nil {
			return fmt.Errorf("apis[%d] %s: %w", i, a.Path, err)
		}
		eff := base.Apply(a.Policy)
		if err := c.checkPolicy("apis "+a.Path, eff); err != nil {
			return err
		}
		for j := range a.Rules {
			r := &a.Rules[j]
			if _, _, err := ParseMatch(r.Match); err != nil {
				return fmt.Errorf("apis[%d] %s rules[%d]: %w", i, a.Path, j, err)
			}
			if err := c.checkPolicy("rule "+r.Match, eff.Apply(r.Policy)); err != nil {
				return err
			}
		}
	}
	for i := range c.Compose {
		p := &c.Compose[i]
		if err := claim(p.Path); err != nil {
			return fmt.Errorf("compose[%d]: %w", i, err)
		}
		if len(p.Steps) == 0 {
			return fmt.Errorf("compose[%d] %s: at least one step is required", i, p.Path)
		}
		if p.Respond == "" {
			return fmt.Errorf("compose[%d] %s: respond is required", i, p.Path)
		}
		if err := c.checkPolicy("compose "+p.Path, base.Apply(p.Policy)); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) checkPolicy(where string, e Effective) error {
	switch e.Token {
	case TokenNone:
	case TokenUser, TokenClient, TokenUserOrClient, TokenUserOrNone:
		if c.OIDC == nil {
			return fmt.Errorf("%s: token %q needs an oidc block", where, e.Token)
		}
	default:
		return fmt.Errorf("%s: unknown token mode %q", where, e.Token)
	}
	if e.Retries < 0 {
		return fmt.Errorf("%s: retries must not be negative", where)
	}
	return nil
}

var (
	placeholderRE = regexp.MustCompile(`\{[^{}]*\}`)
	serviceRE     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)
)

func (a *API) validate() error {
	vars := placeholderRE.FindAllString(a.Path, -1)
	if len(vars) == 0 {
		if len(a.Allow) > 0 {
			return fmt.Errorf("allow only applies to a path with a {name} placeholder")
		}
		if strings.Contains(a.To, "{") {
			return fmt.Errorf("to has a placeholder but path has none")
		}
		return checkURL(a.To)
	}
	if len(vars) > 1 || !strings.HasSuffix(a.Path, "/"+vars[0]) {
		return fmt.Errorf("only one {name} placeholder is allowed, as the last path segment")
	}
	if !strings.Contains(a.To, vars[0]) {
		return fmt.Errorf("to must contain %s", vars[0])
	}
	if len(a.Allow) == 0 {
		return fmt.Errorf("a %s path needs an allow list, or a crafted path could reach any internal host", vars[0])
	}
	for _, name := range a.Allow {
		if !serviceRE.MatchString(name) {
			return fmt.Errorf("allow: %q is not a valid service name", name)
		}
	}
	u, err := url.Parse(strings.ReplaceAll(a.To, vars[0], a.Allow[0]))
	if err != nil || u.Host == "" {
		return fmt.Errorf("to: %q is not an absolute URL", a.To)
	}
	return nil
}

func checkURL(s string) error {
	if s == "" {
		return fmt.Errorf("URL is required")
	}
	u, err := url.Parse(s)
	if err != nil {
		return err
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("%q is not an absolute http(s) URL", s)
	}
	return nil
}

// ParseMatch splits a rule's "GET /x/**" into its method and path pattern.
// An omitted method matches all of them.
func ParseMatch(s string) (method, pattern string, err error) {
	f := strings.Fields(s)
	switch len(f) {
	case 1:
		pattern = f[0]
	case 2:
		method, pattern = strings.ToUpper(f[0]), f[1]
	default:
		return "", "", fmt.Errorf("match %q: want \"[METHOD] /path\"", s)
	}
	if !strings.HasPrefix(pattern, "/") {
		return "", "", fmt.Errorf("match %q: path must start with /", s)
	}
	for i, seg := range strings.Split(pattern, "/") {
		if seg == "**" && i != strings.Count(pattern, "/") {
			return "", "", fmt.Errorf("match %q: ** is only allowed as the last segment", s)
		}
	}
	return method, pattern, nil
}
