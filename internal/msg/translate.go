package msg

import (
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Kodviva/latchwire/internal/msg/icu"
)

// minPatternLiteral is how much fixed text a message needs to be recognised
// by its pattern. Shorter ones ("%s (%d)", the table row) would match
// anything.
const minPatternLiteral = 8

type pattern struct {
	id      string
	re      *regexp.Regexp
	names   []string // one per capture group
	nested  []bool   // the capture is an error: translate it too
	literal int
}

var (
	patternsOnce sync.Once
	exact        map[string]string
	patterns     []*pattern
)

func buildPatterns() {
	en := load()[English]
	exact = map[string]string{}
	for _, e := range en.Entries {
		format, err := icu.GoFormat(e)
		if err != nil {
			continue // a plural message: only ever rendered, never received
		}
		ph := e.Message.Placeholders()
		if len(ph) == 0 {
			exact[e.Text] = e.ID
			continue
		}
		if p := compilePattern(e, format); p != nil {
			patterns = append(patterns, p)
		}
	}
	// The most specific pattern first.
	sort.SliceStable(patterns, func(i, j int) bool { return patterns[i].literal > patterns[j].literal })
}

// verbRe finds the verbs of a GoFormat result.
var verbRe = regexp.MustCompile(`%%|%(?:\[\d+\])?[0-9]*[a-zA-Z]`)

func compilePattern(e *icu.Entry, format string) *pattern {
	p := &pattern{id: e.ID}
	var names []string
	seen := map[string]bool{}
	for _, n := range argOrder(e) {
		if !seen[n] {
			seen[n] = true
			names = append(names, n)
		}
	}
	var b strings.Builder
	b.WriteString(`(?s)^`)
	last, next := 0, 0
	groups := map[string]bool{}
	lit := func(s string) {
		s = strings.ReplaceAll(s, "%%", "%")
		p.literal += len(s)
		b.WriteString(regexp.QuoteMeta(s))
	}
	for _, m := range verbRe.FindAllStringIndex(format, -1) {
		tok := format[m[0]:m[1]]
		if tok == "%%" {
			continue
		}
		lit(format[last:m[0]])
		last = m[1]
		name := ""
		if tok[1] == '[' {
			name = names[int(tok[2]-'1')]
		} else {
			name = names[next]
			next++
		}
		if groups[name] {
			b.WriteString(`.+?`) // a repeat of a captured value
			continue
		}
		groups[name] = true
		p.names = append(p.names, name)
		verb := e.Verb(name)
		p.nested = append(p.nested, verb == "%v" || verb == "%w")
		switch verb {
		case "%d":
			b.WriteString(`(-?\d+)`)
		case "%02x":
			b.WriteString(`([0-9a-f]+)`)
		case "%q":
			b.WriteString(`("(?:[^"\\]|\\.)*")`)
		default:
			b.WriteString(`(.+?)`)
		}
	}
	lit(format[last:])
	b.WriteString(`$`)
	if p.literal < minPatternLiteral {
		return nil
	}
	p.re = regexp.MustCompile(b.String())
	return p
}

// argOrder lists placeholders in order of first appearance.
func argOrder(e *icu.Entry) []string { return e.Message.Args() }

// translateWhole translates s when all of it is one catalog message.
func translateWhole(lang, s string) (string, bool) {
	if id, ok := exact[s]; ok {
		return Render(lang, ID(id), nil), true
	}
	for _, p := range patterns {
		m := p.re.FindStringSubmatch(s)
		if m == nil {
			continue
		}
		args := Args{}
		for i, name := range p.names {
			v := m[i+1]
			if p.nested[i] {
				v = Translate(lang, v)
			}
			args[name] = rawArg(v)
		}
		return renderRaw(lang, ID(p.id), args), true
	}
	return "", false
}

// rawArg marks a value that is already text in its final printf form.
type rawArg string

func renderRaw(lang string, id ID, a Args) string {
	cats := load()
	e := cats[English].ByID[string(id)]
	if f := cats[lang]; f != nil {
		if t := f.ByID[string(id)]; t != nil {
			e = t
		}
	}
	return e.Message.Format(lang, a, func(_ string, v any) string { return string(v.(rawArg)) })
}

// Translate turns English text that came from the daemon, the agent or the
// card code into lang. The text may be one catalog message or several joined
// with "; ", the way the daemon joins status warnings. Text that is not in
// the catalog is returned unchanged: the English original beats nothing.
func Translate(lang, english string) string {
	if lang == English || english == "" {
		return english
	}
	patternsOnce.Do(buildPatterns)
	if s, ok := translateWhole(lang, english); ok {
		return s
	}
	const sep = "; "
	for i := 0; ; {
		j := strings.Index(english[i:], sep)
		if j < 0 {
			return english
		}
		i += j
		if head, ok := translateWhole(lang, english[:i]); ok {
			return head + sep + Translate(lang, english[i+len(sep):])
		}
		i += len(sep)
	}
}
