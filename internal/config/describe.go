package config

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// Describe prints each declared path with its effective settings. Cascaded
// defaults are only trustworthy if they can be inspected.
func (c *Config) Describe(w io.Writer) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "PATH\tTARGET\tTOKEN\tTIMEOUT\tRETRIES\tRATE\tCACHE")
	base := Builtin().Apply(c.Defaults)
	row := func(path, target string, e Effective) {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d\t%s\t%s\n",
			path, target, e.Token, e.Timeout, e.Retries, describeRate(e.RateLimit), describeCache(e))
	}
	for _, a := range c.APIs {
		target := a.To
		if len(a.Allow) > 0 {
			target += " [" + strings.Join(a.Allow, ",") + "]"
		}
		eff := base.Apply(a.Policy)
		row(a.Path, target, eff)
		for _, r := range a.Rules {
			row("  "+r.Match, "(rule)", eff.Apply(r.Policy))
		}
	}
	for _, p := range c.Compose {
		row(p.Path, fmt.Sprintf("(compose, %d steps)", len(p.Steps)), base.Apply(p.Policy))
	}
	tw.Flush()
}

func describeRate(r RateLimit) string {
	if r.Rate == 0 {
		return "off"
	}
	return fmt.Sprintf("%g/s per %s", r.Rate, r.Per)
}

func describeCache(e Effective) string {
	if e.Cache == 0 {
		return "off"
	}
	return e.Cache.String()
}
