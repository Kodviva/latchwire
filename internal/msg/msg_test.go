package msg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/msg/icu"
)

// The texts the CLI and the daemon printed before the move to catalogs:
// existing output must not change. testdata/legacy.json was dumped from the
// hand-written en.go. Messages added later are not in it.
func TestGeneratedMatchesLegacy(t *testing.T) {
	data, err := os.ReadFile("testdata/legacy.json")
	if err != nil {
		t.Fatal(err)
	}
	var legacy map[string]string
	if err := json.Unmarshal(data, &legacy); err != nil {
		t.Fatal(err)
	}
	en := load()[English]
	for id, want := range legacy {
		e := en.ByID[id]
		if e == nil {
			t.Errorf("%s is gone", id)
			continue
		}
		got, err := icu.GoFormat(e)
		if err != nil {
			t.Errorf("%s: %v", id, err)
		} else if got != want {
			t.Errorf("%s changed:\n got %q\nwant %q", id, got, want)
		}
	}
}

func TestGeneratedUpToDate(t *testing.T) {
	want, err := icu.GenerateGo(load()[English])
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("en.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("en.go is out of date: run go generate ./internal/msg")
	}
}

func TestCatalogsComplete(t *testing.T) {
	cats := load()
	en := cats[English]
	for lang, f := range cats {
		if lang == English {
			continue
		}
		for _, e := range en.Entries {
			tr := f.ByID[e.ID]
			if tr == nil {
				t.Errorf("%s: %s is missing", lang, e.ID)
				continue
			}
			if a, b := fmt.Sprint(e.Message.Placeholders()), fmt.Sprint(tr.Message.Placeholders()); a != b {
				t.Errorf("%s: %s: placeholders %s, want %s", lang, e.ID, b, a)
			}
		}
		for _, e := range f.Entries {
			if en.ByID[e.ID] == nil {
				t.Errorf("%s: %s is not in English", lang, e.ID)
			}
		}
	}
}

// sampleArgs gives each placeholder of e a value in its printf form.
func sampleArgs(e *icu.Entry) (Args, []any) {
	a := Args{}
	var list []any
	for i, name := range e.Message.Args() {
		if _, ok := a[name]; ok {
			continue
		}
		var v any = fmt.Sprintf("val%d", i)
		switch e.Verb(name) {
		case "%d":
			v = 7 + i
		case "%02x":
			v = 0x82 + i
		}
		a[name] = v
		list = append(list, v)
	}
	return a, list
}

// Every message that reaches the UI as English text comes out as the
// translated message with the same values.
func TestTranslateRoundTrip(t *testing.T) {
	en := load()[English]
	for _, lang := range Supported() {
		for _, e := range en.Entries {
			if !e.Message.Plain() || strings.HasPrefix(e.ID, "UI") {
				continue
			}
			a, _ := sampleArgs(e)
			source := Render(English, ID(e.ID), a)
			want := Render(lang, ID(e.ID), a)
			got := Translate(lang, source)
			if got != want {
				if lit := literalLen(e); lit < minPatternLiteral && len(e.Message.Placeholders()) > 0 {
					continue // deliberately not recognised
				}
				t.Errorf("%s %s:\n got %q\nwant %q", lang, e.ID, got, want)
			}
		}
	}
}

func literalLen(e *icu.Entry) int {
	s, _ := icu.GoFormat(e)
	return len(regexp.MustCompile(`%(\[\d\])?[0-9]*[a-zA-Z]`).ReplaceAllString(s, ""))
}

func TestMatch(t *testing.T) {
	cases := map[string]string{"tr": "tr", "tr-TR": "tr", "tr_TR.UTF-8": "tr", "en-GB": "en", "xx": "en", "": "en", "TR": "tr"}
	for in, want := range cases {
		if got := Match(in); got != want {
			t.Errorf("%q: %q", in, got)
		}
	}
}

func TestRenderFallsBack(t *testing.T) {
	if got := Render("xx", "PIVSlotEmpty", nil); got != PIVSlotEmpty {
		t.Fatal(got)
	}
	if got := Render("tr", "NoSuchMessage", nil); got != "NoSuchMessage" {
		t.Fatal(got)
	}
}

func TestRenderUsesVerbs(t *testing.T) {
	got := Render(English, "PIVSlotOutOfRangeFmt", Args{"slot": 0x9a})
	if want := fmt.Sprintf(PIVSlotOutOfRangeFmt, 0x9a); got != want {
		t.Fatal(got)
	}
	got = Render(English, "KeyRefInvalidFmt", Args{"ref": "x"})
	if want := fmt.Sprintf(KeyRefInvalidFmt, "x"); got != want {
		t.Fatal(got)
	}
}

func TestTranslateUnknownStaysEnglish(t *testing.T) {
	if got := Translate("tr", "something else entirely"); got != "something else entirely" {
		t.Fatal(got)
	}
}

func TestTranslateJoinedWarnings(t *testing.T) {
	src := DaemonWarnNoRPFilter + "; " + DaemonWarnDNSBusy
	want := Render("tr", "DaemonWarnNoRPFilter", nil) + "; " + Render("tr", "DaemonWarnDNSBusy", nil)
	if got := Translate("tr", src); got != want {
		t.Fatal(got)
	}
}

func TestTranslateNestedError(t *testing.T) {
	src := fmt.Sprintf(DaemonConnectFailedFmt, DaemonNoCard)
	want := Render("tr", "DaemonConnectFailedFmt", Args{"err": Render("tr", "DaemonNoCard", nil)})
	if got := Translate("tr", src); got != want {
		t.Fatal(got)
	}
}
