// Package appsecadapt implements an explicitly bounded subset of CrowdSec
// AppSec conditions. Unsupported operators are rejected before import.
package appsecadapt

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

type Match struct {
	Type  string `json:"type" yaml:"type"`
	Value string `json:"value" yaml:"value"`
}
type Expression struct {
	And       []Expression `json:"and,omitempty" yaml:"and,omitempty"`
	Or        []Expression `json:"or,omitempty" yaml:"or,omitempty"`
	Zones     []string     `json:"zones,omitempty" yaml:"zones,omitempty"`
	Variables []string     `json:"variables,omitempty" yaml:"variables,omitempty"`
	Transform []string     `json:"transform,omitempty" yaml:"transform,omitempty"`
	Match     *Match       `json:"match,omitempty" yaml:"match,omitempty"`
}
type Compiled struct {
	expr    Expression
	and, or []*Compiled
	re      *regexp.Regexp
}

func Compile(e Expression) (*Compiled, error) { n := 0; return compile(e, 0, &n) }
func compile(e Expression, depth int, n *int) (*Compiled, error) {
	*n++
	if *n > 64 || depth > 8 {
		return nil, fmt.Errorf("AppSec: превышен предел сложности (64 условия, глубина 8)")
	}
	c := &Compiled{expr: e}
	if len(e.And) > 0 || len(e.Or) > 0 {
		if len(e.And) > 0 && len(e.Or) > 0 || len(e.Zones) > 0 || len(e.Variables) > 0 || len(e.Transform) > 0 || e.Match != nil {
			return nil, fmt.Errorf("AppSec: логический узел не должен содержать другие условия")
		}
		for _, x := range e.And {
			v, err := compile(x, depth+1, n)
			if err != nil {
				return nil, err
			}
			c.and = append(c.and, v)
		}
		for _, x := range e.Or {
			v, err := compile(x, depth+1, n)
			if err != nil {
				return nil, err
			}
			c.or = append(c.or, v)
		}
		return c, nil
	}
	if len(e.Zones) == 0 || len(e.Zones) > 5 || e.Match == nil || e.Match.Value == "" || len(e.Match.Value) > 4096 {
		return nil, fmt.Errorf("AppSec: нужны zones и непустой match до 4096 байт")
	}
	for _, z := range e.Zones {
		switch z {
		case "URI", "URI_FULL", "METHOD", "RAW_BODY", "HEADERS":
		default:
			return nil, fmt.Errorf("AppSec: зона %s пока не поддерживается", z)
		}
	}
	if len(e.Variables) > 0 {
		if len(e.Zones) != 1 || e.Zones[0] != "HEADERS" || len(e.Variables) > 16 {
			return nil, fmt.Errorf("AppSec: variables поддерживаются только для HEADERS (до 16 имён)")
		}
		for _, v := range e.Variables {
			if v == "" || len(v) > 128 || strings.ContainsAny(v, "/\r\n") {
				return nil, fmt.Errorf("AppSec: шаблоны variables не поддерживаются; нужно точное имя заголовка")
			}
		}
	}
	if len(e.Transform) > 8 {
		return nil, fmt.Errorf("AppSec: слишком много преобразований")
	}
	for _, t := range e.Transform {
		switch t {
		case "lowercase", "uppercase", "trim", "trim_left", "trim_right":
		default:
			return nil, fmt.Errorf("AppSec: преобразование %s пока не поддерживается", t)
		}
	}
	switch e.Match.Type {
	case "equals", "contains", "startsWith", "endsWith":
	case "regex":
		var err error
		c.re, err = regexp.Compile(e.Match.Value)
		if err != nil {
			return nil, fmt.Errorf("AppSec: regex не совместим с RE2: %w", err)
		}
	default:
		return nil, fmt.Errorf("AppSec: match %s пока не поддерживается", e.Match.Type)
	}
	return c, nil
}
func (c *Compiled) Matches(r *http.Request, body []byte) bool {
	if c == nil {
		return false
	}
	if len(c.and) > 0 {
		for _, x := range c.and {
			if !x.Matches(r, body) {
				return false
			}
		}
		return true
	}
	if len(c.or) > 0 {
		for _, x := range c.or {
			if x.Matches(r, body) {
				return true
			}
		}
		return false
	}
	check := func(value string) bool {
		for _, t := range c.expr.Transform {
			switch t {
			case "lowercase":
				value = asciiCase(value, false)
			case "uppercase":
				value = asciiCase(value, true)
			case "trim":
				value = strings.Trim(value, " \t\r\n\v\f")
			case "trim_left":
				value = strings.TrimLeft(value, " \t\r\n\v\f")
			case "trim_right":
				value = strings.TrimRight(value, " \t\r\n\v\f")
			}
		}
		target := c.expr.Match.Value
		switch c.expr.Match.Type {
		case "equals":
			return value == target
		case "contains":
			return strings.Contains(value, target)
		case "startsWith":
			return strings.HasPrefix(value, target)
		case "endsWith":
			return strings.HasSuffix(value, target)
		case "regex":
			return c.re.MatchString(value)
		}
		return false
	}
	for _, z := range c.expr.Zones {
		switch z {
		case "URI":
			if check(r.URL.Path) {
				return true
			}
		case "URI_FULL":
			if check(r.URL.RequestURI()) {
				return true
			}
		case "METHOD":
			if check(r.Method) {
				return true
			}
		case "RAW_BODY":
			if check(string(body)) {
				return true
			}
		case "HEADERS":
			for name, values := range r.Header {
				selected := len(c.expr.Variables) == 0
				for _, v := range c.expr.Variables {
					if strings.EqualFold(v, name) {
						selected = true
					}
				}
				if selected {
					for _, v := range values {
						if check(v) {
							return true
						}
					}
				}
			}
			if r.Host != "" {
				if len(c.expr.Variables) == 0 && check(r.Host) {
					return true
				}
				for _, v := range c.expr.Variables {
					if strings.EqualFold(v, "Host") && check(r.Host) {
						return true
					}
				}
			}
		}
	}
	return false
}
func asciiCase(s string, upper bool) string {
	b := []byte(s)
	for i, v := range b {
		if upper && v >= 'a' && v <= 'z' {
			b[i] = v - 32
		} else if !upper && v >= 'A' && v <= 'Z' {
			b[i] = v + 32
		}
	}
	return string(b)
}
