// Package icu is a small implementation of the ICU MessageFormat subset that
// Latchwire's translations use, and of the ARB files they live in:
//
//	{name}                                  a placeholder
//	{n, plural, =0 {...} one {...} other {...}}   # stands for n
//	{kind, select, a {...} other {...}}
//
// Quoting follows ICU: an apostrophe is literal unless it comes right before
// a brace ('{ starts a quoted run, closed by the next '), and ” is one
// apostrophe. It has no dependency on the message constants, so the
// generator can use it to produce them.
package icu

import (
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type nodeKind int

const (
	nodeText nodeKind = iota
	nodeArg
	nodePlural
	nodeSelect
	nodeHash
)

type node struct {
	kind  nodeKind
	text  string             // nodeText
	name  string             // nodeArg, nodePlural, nodeSelect
	cases map[string]Message // nodePlural, nodeSelect
}

// Message is a parsed message.
type Message []node

type parser struct {
	s    string
	i    int
	hash bool // inside a plural: # is the number
}

// Parse reads one message.
func Parse(s string) (Message, error) {
	p := &parser{s: s}
	m, err := p.message(false)
	if err != nil {
		return nil, fmt.Errorf("%w at offset %d", err, p.i)
	}
	if p.i != len(s) {
		return nil, fmt.Errorf("unexpected } at offset %d", p.i)
	}
	return m, nil
}

func (p *parser) message(nested bool) (Message, error) {
	var out Message
	var b strings.Builder
	flush := func() {
		if b.Len() > 0 {
			out = append(out, node{kind: nodeText, text: b.String()})
			b.Reset()
		}
	}
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '\'':
			p.quote(&b)
		case c == '{':
			flush()
			n, err := p.argument()
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		case c == '}':
			if nested {
				flush()
				return out, nil
			}
			return nil, errors.New("unexpected }")
		case c == '#' && p.hash:
			flush()
			out = append(out, node{kind: nodeHash})
			p.i++
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	if nested {
		return nil, errors.New("unclosed {")
	}
	flush()
	return out, nil
}

// quote handles an apostrophe at p.i.
func (p *parser) quote(b *strings.Builder) {
	next := byte(0)
	if p.i+1 < len(p.s) {
		next = p.s[p.i+1]
	}
	switch {
	case next == '\'':
		b.WriteByte('\'')
		p.i += 2
	case next == '{' || next == '}' || (next == '#' && p.hash):
		p.i++
		for p.i < len(p.s) {
			if p.s[p.i] == '\'' {
				if p.i+1 < len(p.s) && p.s[p.i+1] == '\'' {
					b.WriteByte('\'')
					p.i += 2
					continue
				}
				p.i++
				return
			}
			b.WriteByte(p.s[p.i])
			p.i++
		}
	default:
		b.WriteByte('\'')
		p.i++
	}
}

func (p *parser) space() {
	for p.i < len(p.s) && strings.IndexByte(" \t\r\n", p.s[p.i]) >= 0 {
		p.i++
	}
}

func (p *parser) word() string {
	p.space()
	start := p.i
	for p.i < len(p.s) && strings.IndexByte(" \t\r\n,{}", p.s[p.i]) < 0 {
		p.i++
	}
	return p.s[start:p.i]
}

func (p *parser) argument() (node, error) {
	p.i++ // {
	name := p.word()
	if name == "" {
		return node{}, errors.New("empty placeholder")
	}
	p.space()
	if p.i >= len(p.s) {
		return node{}, errors.New("unclosed {")
	}
	switch p.s[p.i] {
	case '}':
		p.i++
		return node{kind: nodeArg, name: name}, nil
	case ',':
		p.i++
	default:
		return node{}, fmt.Errorf("bad placeholder %q", name)
	}
	typ := p.word()
	p.space()
	if p.i >= len(p.s) || p.s[p.i] != ',' {
		return node{}, fmt.Errorf("placeholder %q: expected , after %s", name, typ)
	}
	p.i++
	var kind nodeKind
	switch typ {
	case "plural":
		kind = nodePlural
	case "select":
		kind = nodeSelect
	default:
		return node{}, fmt.Errorf("placeholder %q: unknown type %q", name, typ)
	}
	n := node{kind: kind, name: name, cases: map[string]Message{}}
	for {
		key := p.word()
		p.space()
		if key == "" {
			if p.i < len(p.s) && p.s[p.i] == '}' {
				p.i++
				break
			}
			return node{}, fmt.Errorf("placeholder %q: expected a case", name)
		}
		if p.i >= len(p.s) || p.s[p.i] != '{' {
			return node{}, fmt.Errorf("placeholder %q: expected { after %s", name, key)
		}
		p.i++
		outer := p.hash
		p.hash = kind == nodePlural || outer
		c, err := p.message(true)
		p.hash = outer
		if err != nil {
			return node{}, err
		}
		p.i++ // }
		n.cases[key] = c
	}
	if _, ok := n.cases["other"]; !ok {
		return node{}, fmt.Errorf("placeholder %q: no other case", name)
	}
	return n, nil
}

// Placeholders returns the names a message refers to, sorted, without
// duplicates.
func (m Message) Placeholders() []string {
	seen := map[string]bool{}
	var walk func(Message)
	walk = func(m Message) {
		for _, n := range m {
			switch n.kind {
			case nodeArg:
				seen[n.name] = true
			case nodePlural, nodeSelect:
				seen[n.name] = true
				for _, c := range n.cases {
					walk(c)
				}
			}
		}
	}
	walk(m)
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// Args lists the plain placeholders in order of first appearance, repeats
// included.
func (m Message) Args() []string {
	var out []string
	for _, n := range m {
		if n.kind == nodeArg {
			out = append(out, n.name)
		}
	}
	return out
}

// Plain reports whether the message has neither plural nor select, so it can
// be expressed as a printf format.
func (m Message) Plain() bool {
	for _, n := range m {
		if n.kind == nodePlural || n.kind == nodeSelect {
			return false
		}
	}
	return true
}

// Format renders m. str turns a placeholder's value into text; an unknown
// placeholder stays visible as {name}, so a missing argument is noticed and
// never breaks a message.
func (m Message) Format(lang string, args map[string]any, str func(name string, v any) string) string {
	var b strings.Builder
	m.format(&b, lang, args, str, "")
	return b.String()
}

func (m Message) format(b *strings.Builder, lang string, args map[string]any, str func(string, any) string, hash string) {
	for _, n := range m {
		switch n.kind {
		case nodeText:
			b.WriteString(n.text)
		case nodeHash:
			b.WriteString(hash)
		case nodeArg:
			v, ok := args[n.name]
			if !ok {
				b.WriteString("{" + n.name + "}")
				continue
			}
			b.WriteString(str(n.name, v))
		case nodeSelect:
			c, ok := n.cases[fmt.Sprint(args[n.name])]
			if !ok {
				c = n.cases["other"]
			}
			c.format(b, lang, args, str, hash)
		case nodePlural:
			num := toInt(args[n.name])
			c, ok := n.cases["="+strconv.Itoa(num)]
			if !ok {
				if c, ok = n.cases[PluralCategory(lang, num)]; !ok {
					c = n.cases["other"]
				}
			}
			c.format(b, lang, args, str, strconv.Itoa(num))
		}
	}
}

func toInt(v any) int {
	switch x := v.(type) {
	case int:
		return x
	case int64:
		return int(x)
	case uint32:
		return int(x)
	case uint8:
		return int(x)
	case string:
		n, _ := strconv.Atoi(x)
		return n
	}
	return 0
}
