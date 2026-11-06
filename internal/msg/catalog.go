package msg

import (
	"embed"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/Kodviva/latchwire/internal/msg/icu"
)

// English is the source language.
const English = "en"

//go:embed locales/*.arb
var localeFiles embed.FS

// ID names a message in the catalogs.
type ID string

// Args are a message's placeholder values, by name.
type Args map[string]any

var (
	loadOnce sync.Once
	catalogs map[string]*icu.File
)

// load parses the catalogs once, on first use: the CLI and the daemon never
// get here. A broken embedded catalog is a programming error that
// TestCatalogsComplete catches.
func load() map[string]*icu.File {
	loadOnce.Do(func() {
		catalogs = map[string]*icu.File{}
		names, err := localeFiles.ReadDir("locales")
		if err != nil {
			panic(err)
		}
		for _, n := range names {
			data, err := localeFiles.ReadFile("locales/" + n.Name())
			if err != nil {
				panic(err)
			}
			f, err := icu.ParseARB(data)
			if err != nil {
				panic(fmt.Sprintf("msg: %s: %v", n.Name(), err))
			}
			catalogs[f.Locale] = f
		}
	})
	return catalogs
}

// Supported lists the languages with a catalog, sorted.
func Supported() []string {
	var out []string
	for l := range load() {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
}

// Match picks the catalog for a language tag such as "tr-TR", "tr_TR.UTF-8"
// or "pt-BR", English when there is none.
func Match(tag string) string {
	tag, _, _ = strings.Cut(tag, ".")
	tag = strings.ReplaceAll(tag, "_", "-")
	cats := load()
	for l := range cats {
		if strings.EqualFold(l, tag) {
			return l
		}
	}
	base, _, _ := strings.Cut(tag, "-")
	for l := range cats {
		if strings.EqualFold(l, base) {
			return l
		}
	}
	return English
}

// Render formats a message in lang. A language or message that is missing
// falls back to English, and a message missing from English too shows its
// ID, so a mistake stays visible without breaking the screen.
func Render(lang string, id ID, a Args) string {
	cats := load()
	en := cats[English].ByID[string(id)]
	if en == nil {
		return string(id)
	}
	e := en
	if f := cats[lang]; f != nil {
		if t := f.ByID[string(id)]; t != nil {
			e = t
		}
	}
	return e.Message.Format(lang, a, func(name string, v any) string {
		verb := en.Verb(name)
		if verb == "%w" {
			verb = "%v"
		}
		return fmt.Sprintf(verb, v)
	})
}
