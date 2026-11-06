package icu

import (
	"fmt"
	"testing"
)

func render(t *testing.T, lang, s string, args map[string]any) string {
	t.Helper()
	m, err := Parse(s)
	if err != nil {
		t.Fatalf("Parse(%q): %v", s, err)
	}
	return m.Format(lang, args, func(_ string, v any) string { return fmt.Sprint(v) })
}

func TestPlaceholders(t *testing.T) {
	got := render(t, "en", "tunnel {name} is {state}", map[string]any{"name": "ofis", "state": "up"})
	if got != "tunnel ofis is up" {
		t.Fatal(got)
	}
}

func TestMissingPlaceholderStaysVisible(t *testing.T) {
	if got := render(t, "en", "a {b} c", nil); got != "a {b} c" {
		t.Fatal(got)
	}
}

func TestPlural(t *testing.T) {
	const s = "{n, plural, =0 {no tunnels} one {# tunnel} other {# tunnels}}"
	for n, want := range map[int]string{0: "no tunnels", 1: "1 tunnel", 5: "5 tunnels"} {
		if got := render(t, "en", s, map[string]any{"n": n}); got != want {
			t.Errorf("%d: %q", n, got)
		}
	}
}

func TestPluralRussian(t *testing.T) {
	const s = "{n, plural, one {# туннель} few {# туннеля} many {# туннелей} other {# туннеля}}"
	for n, want := range map[int]string{1: "1 туннель", 3: "3 туннеля", 5: "5 туннелей", 11: "11 туннелей", 21: "21 туннель", 22: "22 туннеля"} {
		if got := render(t, "ru", s, map[string]any{"n": n}); got != want {
			t.Errorf("%d: %q", n, got)
		}
	}
}

func TestPluralCategories(t *testing.T) {
	cases := []struct {
		lang string
		n    int
		want string
	}{
		{"ja", 1, "other"}, {"zh-Hans", 1, "other"}, {"ko", 2, "other"},
		{"tr", 1, "one"}, {"tr", 2, "other"},
		{"fr", 0, "one"}, {"fr", 1, "one"}, {"fr", 2, "other"}, {"fr", 1000000, "many"},
		{"pt-BR", 0, "one"}, {"es", 0, "other"}, {"es", 1, "one"}, {"de", 1, "one"},
	}
	for _, c := range cases {
		if got := PluralCategory(c.lang, c.n); got != c.want {
			t.Errorf("%s %d: %s", c.lang, c.n, got)
		}
	}
}

func TestSelectNestedPlural(t *testing.T) {
	const s = "{k, select, a {{n, plural, one {# x} other {# xs}}} other {none}}"
	if got := render(t, "en", s, map[string]any{"k": "a", "n": 2}); got != "2 xs" {
		t.Fatal(got)
	}
	if got := render(t, "en", s, map[string]any{"k": "b"}); got != "none" {
		t.Fatal(got)
	}
}

func TestApostrophes(t *testing.T) {
	cases := map[string]string{
		"the tunnel's name": "the tunnel's name",
		"it''s":             "it's",
		"a '{literal}' b":   "a {literal} b",
		"100% # sure":       "100% # sure",
	}
	for in, want := range cases {
		if got := render(t, "en", in, nil); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestParseErrors(t *testing.T) {
	for _, s := range []string{"{", "}", "{a", "{}", "{a, plural, one {x}}", "{a, number, x}", "{a, plural, other {x}", "{a b}"} {
		if _, err := Parse(s); err == nil {
			t.Errorf("Parse(%q) succeeded", s)
		}
	}
}

func TestGoFormat(t *testing.T) {
	f, err := ParseARB([]byte(`{"@@locale":"en",
		"A":"slot {slot} on {serial}: 5%",
		"@A":{"placeholders":{"slot":{"verb":"%02x"},"serial":{"verb":"%d"}}},
		"B":"{x} and {x} and {y}",
		"C":"100%"}`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"A": "slot %02x on %d: 5%%", "B": "%[1]s and %[1]s and %[2]s", "C": "100%"}
	for id, w := range want {
		if got, err := GoFormat(f.ByID[id]); err != nil || got != w {
			t.Errorf("%s: %q, %v", id, got, err)
		}
	}
}

func TestARBRejectsDuplicates(t *testing.T) {
	if _, err := ParseARB([]byte(`{"A":"x","A":"y"}`)); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err := ParseARB([]byte(`{"@A":{}}`)); err == nil {
		t.Fatal("metadata without a message accepted")
	}
}
