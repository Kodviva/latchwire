package ui

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/test"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/desktop/demo"
	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// contains reports whether o shows s somewhere inside it.
func contains(o fyne.CanvasObject, s string) bool {
	found := false
	var visit func(o fyne.CanvasObject)
	visit = func(o fyne.CanvasObject) {
		switch w := o.(type) {
		case *widget.RichText:
			found = found || strings.Contains(w.String(), s)
		case *fyne.Container:
			for _, c := range w.Objects {
				visit(c)
			}
		case fyne.Widget:
			for _, c := range test.WidgetRenderer(w).Objects() {
				visit(c)
			}
		}
	}
	visit(o)
	return found
}

// tapEntry taps the sidebar or roadmap entry that shows s.
func tapEntry(t *testing.T, u *UI, s string) {
	t.Helper()
	var found *tapCard
	walk(u, func(o fyne.CanvasObject) {
		if c, ok := o.(*tapCard); ok && found == nil && contains(c.content, s) {
			found = c
		}
	})
	if found == nil {
		t.Fatalf("no entry %q on:\n%s", s, screenText(u))
	}
	test.Tap(found)
}

func openAccess(t *testing.T, u *UI) {
	t.Helper()
	tapEntry(t, u, en(msg.UIAccessNav))
	if u.screen != screenAccess {
		t.Fatalf("screen = %v, want access", u.screen)
	}
}

func TestAccessScreenOffByDefault(t *testing.T) {
	u, b := start(t, "en")
	openAccess(t, u)
	wantText(t, u, en(msg.UIAccessStateOff))
	wantText(t, u, en(msg.UIAccess60))
	button(t, u, en(msg.UIAccessTurnOn))
	noText(t, u, en(msg.UIAccessTurnOff))
	if len(b.Grants()) != 0 || b.GrantHeld() {
		t.Fatal("access opened by itself")
	}
	var checks []*widget.Check
	walk(u, func(o fyne.CanvasObject) {
		if c, ok := o.(*widget.Check); ok {
			checks = append(checks, c)
		}
	})
	if len(checks) != 3 || !checks[0].Checked || !checks[1].Checked || !checks[2].Checked {
		t.Fatalf("group boxes %d, all checked: %v", len(checks), checks)
	}
}

func TestAccessGrantDefaults(t *testing.T) {
	u, b := start(t, "en")
	openAccess(t, u)
	tap(t, u, en(msg.UIAccessTurnOn))
	eventually(t, "grant", func() bool { return len(b.Grants()) == 1 })
	g := b.Grants()[0]
	if g.Minutes != 60 || !slices.Equal(g.Groups, []string{ipc.GroupKeys, ipc.GroupTunnels, ipc.GroupConnect}) {
		t.Fatalf("grant %+v", g)
	}
	eventually(t, "on", func() bool { return strings.Contains(screenText(u), "60 minutes left") })
	button(t, u, en(msg.UIAccessTurnOff))
}

func TestAccessGrantChoices(t *testing.T) {
	u, b := start(t, "tr")
	u.show(screenAccess)
	var sel *widget.Select
	walk(u, func(o fyne.CanvasObject) {
		if s, ok := o.(*widget.Select); ok && slices.Contains(s.Options, msg.Render("tr", msg.UIAccess60, nil)) {
			sel = s
		}
	})
	if sel == nil || sel.Selected != "1 saat" || len(sel.Options) != 3 {
		t.Fatalf("duration %+v", sel)
	}
	sel.SetSelectedIndex(2)
	walk(u, func(o fyne.CanvasObject) {
		if c, ok := o.(*widget.Check); ok && c.Text == msg.Render("tr", msg.UIAccessGroupTunnels, nil) {
			c.SetChecked(false)
		}
	})
	tap(t, u, "Aç")
	eventually(t, "grant", func() bool { return len(b.Grants()) == 1 })
	if g := b.Grants()[0]; g.Minutes != 0 || !slices.Equal(g.Groups, []string{ipc.GroupKeys, ipc.GroupConnect}) {
		t.Fatalf("grant %+v", g)
	}
	eventually(t, "on", func() bool { return strings.Contains(screenText(u), "Latchwire kapanana kadar açık") })
}

func TestAccessRevoke(t *testing.T) {
	u, b := start(t, "en")
	openAccess(t, u)
	tap(t, u, en(msg.UIAccessTurnOn))
	eventually(t, "on", func() bool { return strings.Contains(screenText(u), en(msg.UIAccessTurnOff)) })

	// A waiting approval is refused when access is turned off.
	res := make(chan bool, 1)
	go func() {
		ok, _ := u.Approve(context.Background(), ipc.ApproveRequest{ID: "a1", Client: "claude-code", Tool: ipc.ToolConnect})
		res <- ok
	}()
	eventually(t, "approval", func() bool { return strings.Contains(screenText(u), en(msg.UIApproveAllow)) })
	tap(t, u, en(msg.UIAccessTurnOff))
	select {
	case ok := <-res:
		if ok {
			t.Fatal("allowed after revoke")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the approval stayed open after revoke")
	}
	eventually(t, "revoked", func() bool { return b.Revokes() == 1 && !b.GrantHeld() })
	eventually(t, "off", func() bool { return strings.Contains(screenText(u), en(msg.UIAccessStateOff)) })
	noText(t, u, en(msg.UIApproveAllow))
}

// Access ends with the agent connection that opened it, and at its time.
func TestAccessEndsWithConnectionAndTime(t *testing.T) {
	u, b := start(t, "en")
	openAccess(t, u)
	tap(t, u, en(msg.UIAccessTurnOn))
	eventually(t, "on", func() bool { return b.GrantHeld() })
	b.DropGrant()
	sync(u)
	eventually(t, "off", func() bool { return strings.Contains(screenText(u), en(msg.UIAccessStateOff)) })

	tap(t, u, en(msg.UIAccessTurnOn))
	eventually(t, "on again", func() bool { return strings.Contains(screenText(u), en(msg.UIAccessTurnOff)) })
	u.access.until = time.Now().Add(-time.Second)
	sync(u)
	eventually(t, "expired", func() bool { return strings.Contains(screenText(u), en(msg.UIAccessStateOff)) })
}

func TestAccessActivityHidesChecked(t *testing.T) {
	u, b := start(t, "en")
	now := time.Now()
	b.SetActivity([]ipc.ActivityEntry{
		{Time: now, Client: "claude-code", Tool: ipc.ToolCreateKey, Summary: "new key on YubiKey 40727512, slot 82", Result: "denied"},
		{Time: now, Client: "claude-code", Tool: ipc.ToolAddTunnel, Summary: "probe-only", Result: "checked"},
		{Time: now, Client: "claude-code", Tool: ipc.ToolStatus, Result: "done"},
	})
	openAccess(t, u)
	eventually(t, "activity", func() bool { return strings.Contains(screenText(u), "create_key") })
	wantText(t, u, en(msg.UIAccessResultDenied))
	wantText(t, u, "status")
	noText(t, u, "probe-only")
	noText(t, u, "add_tunnel")
}

func TestAccessActivityTranslatesSummary(t *testing.T) {
	u, b := start(t, "tr")
	b.SetActivity([]ipc.ActivityEntry{{Time: time.Now(), Client: "claude-code", Tool: ipc.ToolCreateKey,
		Summary: "new key on YubiKey 40727512, slot 82", Result: "done"}})
	u.show(screenAccess)
	eventually(t, "translated", func() bool { return strings.Contains(screenText(u), "40727512 seri numaralı YubiKey'de yeni anahtar") })
	wantText(t, u, "yapıldı")
}

func TestAccessActivityRefreshes(t *testing.T) {
	u, b := start(t, "en")
	u.show(screenAccess)
	time.Sleep(20 * time.Millisecond)
	b.SetActivity([]ipc.ActivityEntry{{Time: time.Now(), Client: "claude-code", Tool: ipc.ToolDisconnect, Result: "done"}})
	u.access.fetched = time.Now().Add(-activityEvery)
	sync(u)
	eventually(t, "refreshed", func() bool { return strings.Contains(screenText(u), "disconnect") })
}

func approve(u *UI, ctx context.Context, r ipc.ApproveRequest) chan bool {
	res := make(chan bool, 1)
	go func() {
		ok, err := u.Approve(ctx, r)
		if err != nil {
			ok = false
		}
		res <- ok
	}()
	return res
}

func answer(t *testing.T, res chan bool) bool {
	t.Helper()
	select {
	case ok := <-res:
		return ok
	case <-time.After(5 * time.Second):
		t.Fatal("Approve did not return")
	}
	return false
}

func TestApproveDialogAllowDeny(t *testing.T) {
	u, _ := start(t, "en")
	r := ipc.ApproveRequest{ID: "a1", Client: "claude-code", Tool: ipc.ToolCreateKey, Summary: "new key on YubiKey 40727512, slot 82"}
	res := approve(u, context.Background(), r)
	eventually(t, "dialog", func() bool { return strings.Contains(screenText(u), en(msg.UIApproveTitle)) })
	wantText(t, u, "Agent: “claude-code”")
	wantText(t, u, en(msg.UIApproveToolCreateKey))
	wantText(t, u, "new key on YubiKey 40727512, slot 82")
	noText(t, u, en(msg.UIApproveFresh))
	if b := button(t, u, en(msg.UIApproveAllow)); b.Importance == widget.HighImportance {
		t.Fatal("Allow is the default button")
	}
	tap(t, u, en(msg.UIApproveAllow))
	if !answer(t, res) {
		t.Fatal("Allow returned false")
	}
	noText(t, u, en(msg.UIApproveTitle))

	res = approve(u, context.Background(), r)
	eventually(t, "dialog", func() bool { return strings.Contains(screenText(u), en(msg.UIApproveTitle)) })
	tap(t, u, en(msg.UIApproveDeny))
	if answer(t, res) {
		t.Fatal("Deny returned true")
	}
	noText(t, u, en(msg.UIApproveTitle))
}

func TestApproveDialogTranslated(t *testing.T) {
	u, _ := start(t, "tr")
	res := approve(u, context.Background(), ipc.ApproveRequest{Client: "claude-code", Tool: ipc.ToolCreateKey,
		Summary: "new key on YubiKey 40727512, slot 82"})
	eventually(t, "dialog", func() bool { return strings.Contains(screenText(u), "İzin ver") })
	wantText(t, u, "40727512 seri numaralı YubiKey'de yeni anahtar")
	tap(t, u, "Reddet")
	if answer(t, res) {
		t.Fatal("allowed")
	}
}

func TestApproveDialogClosesOnCancel(t *testing.T) {
	u, _ := start(t, "en")
	r := ipc.ApproveRequest{ID: "a1", Client: "claude-code", Tool: ipc.ToolConnect}

	ctx, cancel := context.WithCancel(context.Background())
	res := approve(u, ctx, r)
	eventually(t, "dialog", func() bool { return strings.Contains(screenText(u), en(msg.UIApproveTitle)) })
	cancel()
	if answer(t, res) {
		t.Fatal("cancel allowed")
	}
	noText(t, u, en(msg.UIApproveTitle))

	old := approveTimeout
	approveTimeout = 30 * time.Millisecond
	defer func() { approveTimeout = old }()
	res = approve(u, context.Background(), r)
	if answer(t, res) {
		t.Fatal("timeout allowed")
	}
	eventually(t, "closed", func() bool { return !strings.Contains(screenText(u), en(msg.UIApproveTitle)) })
}

func TestApproveFreshWarns(t *testing.T) {
	u, _ := start(t, "en")
	res := approve(u, context.Background(), ipc.ApproveRequest{Client: "claude-code", Tool: ipc.ToolCreateKey, Fresh: true})
	eventually(t, "dialog", func() bool { return strings.Contains(screenText(u), en(msg.UIApproveTitle)) })
	wantText(t, u, "factory PIN and PUK")
	tap(t, u, en(msg.UIApproveDeny))
	answer(t, res)
}

func TestNoticeMarksStep(t *testing.T) {
	u, _ := startGuided(t, ownerSurvey(desktop.HelpGuided))
	u.Notice(string(desktop.StepKeyCreated))
	eventually(t, "marked", func() bool {
		p := storedProgress(u)
		return p[desktop.StepKeyCreated] && p[desktop.StepCardReady]
	})
	u.Notice("no_such_step")
	time.Sleep(20 * time.Millisecond)
	if storedProgress(u)["no_such_step"] {
		t.Fatal("an unknown step was stored")
	}
}

func TestExpertSeesOnlySidebarEntry(t *testing.T) {
	u, _ := start(t, "en")
	wantText(t, u, en(msg.UIAccessNav))
	u.show(screenRoadmap)
	noText(t, u, en(msg.UIRoadmapAgentLink))
	TestExpertScreensUnchanged(t)
}

func TestRoadmapLinksToAccess(t *testing.T) {
	for _, h := range []desktop.HelpLevel{desktop.HelpGuided, desktop.HelpHints} {
		u, _ := startGuided(t, ownerSurvey(h))
		u.show(screenRoadmap)
		tapEntry(t, u, en(msg.UIRoadmapAgentLink))
		if u.screen != screenAccess {
			t.Fatalf("%s: screen = %v", h, u.screen)
		}
	}
}

func TestSetupCommandUsesInstalledPath(t *testing.T) {
	name := "latchwire"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dir := t.TempDir()
	old := executable
	defer func() { executable = old }()
	executable = func() (string, error) { return filepath.Join(dir, "latchwire-desktop"), nil }

	want := map[string]string{"darwin": "/usr/local/latchwire/bin/latchwire", "linux": "/usr/bin/latchwire",
		"windows": `C:\Program Files\Latchwire\latchwire.exe`}[runtime.GOOS]
	if got := latchwirePath(); want != "" && got != want {
		t.Fatalf("no binary beside the app: %q, want %q", got, want)
	}
	beside := filepath.Join(dir, name)
	if err := os.WriteFile(beside, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := latchwirePath(); got != beside {
		t.Fatalf("got %q, want %q", got, beside)
	}

	u, _ := start(t, "en")
	u.show(screenAccess)
	wantText(t, u, "claude mcp add latchwire -- "+beside+" mcp")
	var cfg struct {
		MCPServers map[string]struct {
			Command string   `json:"command"`
			Args    []string `json:"args"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(desktopConfig(beside)), &cfg); err != nil {
		t.Fatal(err)
	}
	if s := cfg.MCPServers["latchwire"]; s.Command != beside || !slices.Equal(s.Args, []string{"mcp"}) {
		t.Fatalf("%+v", cfg)
	}
	wantText(t, u, beside+" mcp")
	if got := claudeCommand(`C:\Program Files\Latchwire\latchwire.exe`); got != `claude mcp add latchwire -- "C:\Program Files\Latchwire\latchwire.exe" mcp` {
		t.Fatal(got)
	}
}

func TestCardListForAgent(t *testing.T) {
	u, b := start(t, "en")
	b.SetFresh(demo.CardB, true)
	if _, err := b.Keygen(demo.CardA, 0x82, stubAsker{}); err != nil {
		t.Fatal(err)
	}
	cards, err := u.CardList()
	if err != nil || len(cards) != 2 {
		t.Fatalf("%+v, %v", cards, err)
	}
	a, c := cards[0], cards[1]
	if a.Serial != demo.CardA || a.Fresh || !a.Supported || len(a.Keys) != 1 || a.Keys[0] != "piv://40727512/82" ||
		slices.Contains(a.FreeSlots, 0x82) || len(a.FreeSlots) != 19 {
		t.Fatalf("card A %+v", a)
	}
	if c.Serial != demo.CardB || !c.Fresh || len(c.FreeSlots) != 20 {
		t.Fatalf("card B %+v", c)
	}
}

// A key the daemon asks for goes through the same PIN form, and the
// request's end closes the form.
func TestKeygenForAgent(t *testing.T) {
	u, _ := start(t, "en")
	type result struct {
		k   desktop.Key
		err error
	}
	res := make(chan result, 1)
	go func() {
		k, err := u.KeygenFor(context.Background(), demo.CardA, 0x83)
		res <- result{k, err}
	}()
	eventually(t, "PIN form", func() bool { return len(fields(u)) == 1 })
	typeInto(fields(u)[0], "123456")
	tap(t, u, "OK")
	r := <-res
	if r.err != nil || r.k.Ref.Serial != demo.CardA || r.k.Ref.Slot != 0x83 {
		t.Fatalf("%+v", r)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		k, err := u.KeygenFor(ctx, demo.CardA, 0x84)
		res <- result{k, err}
	}()
	eventually(t, "PIN form", func() bool { return len(fields(u)) == 1 })
	typeInto(fields(u)[0], "1234")
	f := fields(u)[0]
	cancel()
	select {
	case r := <-res:
		if !errors.Is(r.err, desktop.ErrCancelled) {
			t.Fatalf("err %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the PIN form stayed after the request ended")
	}
	if len(fields(u)) != 0 || f.Len() != 0 {
		t.Fatal("the form or its input stayed")
	}
}
