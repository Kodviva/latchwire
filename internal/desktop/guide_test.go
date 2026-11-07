package desktop

import (
	"slices"
	"testing"
)

func TestRoadmapInvited(t *testing.T) {
	got := Roadmap(Survey{Path: PathInvited, Help: HelpGuided})
	want := []StepID{StepCardReady, StepKeyCreated, StepBackupOffered, StepPubkeyShared, StepServerInfo, StepConnected}
	if !slices.Equal(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
}

func TestRoadmapOwner(t *testing.T) {
	got := Roadmap(Survey{Path: PathOwner, Server: ServerOPNsense, Help: HelpHints})
	want := []StepID{StepCardReady, StepKeyCreated, StepBackupOffered, StepServerAdded, StepServerInfo, StepConnected}
	if !slices.Equal(got, want) {
		t.Fatalf("%v, want %v", got, want)
	}
}

func TestRoadmapExploreAndExpertAreEmpty(t *testing.T) {
	if r := Roadmap(Survey{Path: PathExplore, Help: HelpGuided}); len(r) != 0 {
		t.Fatal(r)
	}
	if r := Roadmap(Survey{Path: PathOwner, Help: HelpExpert}); len(r) != 0 {
		t.Fatal(r)
	}
}

func TestProgressCurrent(t *testing.T) {
	steps := Roadmap(Survey{Path: PathInvited, Help: HelpGuided})
	p := Progress{StepCardReady: true, StepKeyCreated: true}
	if id, ok := p.Current(steps); !ok || id != StepBackupOffered {
		t.Fatal(id, ok)
	}
	for _, s := range steps {
		p[s] = true
	}
	if _, ok := p.Current(steps); ok {
		t.Fatal("finished roadmap has a current step")
	}
}

func TestSurveyRoundTrip(t *testing.T) {
	s := Survey{Path: PathOwner, Card: CardUnsure, Help: HelpHints, Server: ServerMikroTik}
	if got, ok := DecodeSurvey(s.Encode()); !ok || got != s {
		t.Fatal(got, ok)
	}
	if _, ok := DecodeSurvey("path=bogus"); ok {
		t.Fatal("bad value accepted")
	}
	p := Progress{StepKeyCreated: true}
	if got := DecodeProgress(p.Encode()); !got[StepKeyCreated] || len(got) != 1 {
		t.Fatal(got)
	}
}

func TestEncodeIsStableAndDecodeRejectsJunk(t *testing.T) {
	s := Survey{Path: PathInvited, Help: HelpGuided}
	if got, want := s.Encode(), "card=;help=guided;path=invited;server="; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	if got, ok := DecodeSurvey(s.Encode()); !ok || got != s {
		t.Fatal(got, ok)
	}
	for _, v := range []string{"", "garbage", "path=owner;help=bogus", "path=owner;help=hints;extra=1", "path=owner;help=hints;card=nope"} {
		if _, ok := DecodeSurvey(v); ok {
			t.Fatalf("%q accepted", v)
		}
	}
	p := Progress{StepConnected: true, StepCardReady: true, StepKeyCreated: false}
	if got, want := p.Encode(), "card_ready=1;connected=1"; got != want {
		t.Fatalf("%q, want %q", got, want)
	}
	if got := DecodeProgress("card_ready=1;bogus=1;connected=0;junk"); len(got) != 1 || !got[StepCardReady] {
		t.Fatal(got)
	}
	if got := DecodeProgress(""); got == nil || len(got) != 0 {
		t.Fatal(got)
	}
}
