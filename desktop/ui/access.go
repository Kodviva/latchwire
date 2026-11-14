package ui

import (
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// activityEvery paces the activity list's refresh while its screen is open.
const activityEvery = 5 * time.Second

// accessTimeout bounds the grant, revoke and activity calls.
const accessTimeout = 10 * time.Second

// accessDurations are the choices of how long access stays open, in the
// order shown; minutes 0 is until the app quits.
var accessDurations = []struct {
	minutes int
	label   msg.ID
}{
	{15, msg.UIAccess15},
	{60, msg.UIAccess60},
	{0, msg.UIAccessUntilQuit},
}

// defaultDuration is the index of 1 hour.
const defaultDuration = 1

// accessGroups are the permission groups, in the order shown and sent.
var accessGroups = []struct {
	group string
	label msg.ID
}{
	{ipc.GroupKeys, msg.UIAccessGroupKeys},
	{ipc.GroupTunnels, msg.UIAccessGroupTunnels},
	{ipc.GroupConnect, msg.UIAccessGroupConnect},
}

// accessState is the agent access screen and the approval windows open.
type accessState struct {
	on    bool
	until time.Time // zero: until the app quits
	// choice is the index in accessDurations; unchecked holds the groups
	// the user unticked. Both survive turning access off and on.
	choice    int
	unchecked map[string]bool
	working   bool

	entries  []ipc.ActivityEntry
	fetched  time.Time
	fetching bool

	status    *widget.RichText // the state line, updated in place
	approvals map[*struct{}]context.CancelFunc
}

func newAccessState() accessState {
	return accessState{choice: defaultDuration, unchecked: map[string]bool{},
		approvals: map[*struct{}]context.CancelFunc{}}
}

// executable is os.Executable and statFile os.Stat; tests replace them.
var (
	executable = os.Executable
	statFile   = os.Stat
)

// latchwirePath is the latchwire command an agent client starts: the one
// beside this app if there is one, else where the platform's package
// installs it (on Linux /usr/bin, or /usr/local/bin when only that one
// exists).
func latchwirePath() string { return latchwirePathFor(runtime.GOOS) }

// isFile reports whether p is a regular file.
func isFile(p string) bool {
	st, err := statFile(p)
	return err == nil && st.Mode().IsRegular()
}

func latchwirePathFor(goos string) string {
	name := "latchwire"
	if goos == "windows" {
		name += ".exe"
	}
	if exe, err := executable(); err == nil {
		if p := filepath.Join(filepath.Dir(exe), name); isFile(p) {
			return p
		}
	}
	switch goos {
	case "darwin":
		return "/usr/local/latchwire/bin/latchwire"
	case "windows":
		return `C:\Program Files\Latchwire\latchwire.exe`
	}
	// Linux: the package's place, else a manual install's.
	for _, p := range []string{"/usr/bin/latchwire", "/usr/local/bin/latchwire"} {
		if isFile(p) {
			return p
		}
	}
	return "/usr/bin/latchwire"
}

// shellQuote quotes path for a command line when it has a space.
func shellQuote(path string) string {
	if strings.ContainsAny(path, " \t") {
		return `"` + path + `"`
	}
	return path
}

// claudeCommand adds Latchwire to Claude Code.
func claudeCommand(path string) string {
	return "claude mcp add latchwire -- " + shellQuote(path) + " mcp"
}

// desktopConfig is the Claude Desktop configuration entry.
func desktopConfig(path string) string {
	type server struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	b, _ := json.MarshalIndent(map[string]map[string]server{
		"mcpServers": {"latchwire": {Command: path, Args: []string{"mcp"}}},
	}, "", "  ")
	return string(b)
}

// accessText is the state line.
func (u *UI) accessText() string {
	a := &u.access
	switch {
	case !a.on:
		return u.t(msg.UIAccessStateOff)
	case a.until.IsZero():
		return u.t(msg.UIAccessStateUntilQuit)
	}
	left := int(math.Ceil(time.Until(a.until).Minutes()))
	return u.tr(msg.UIAccessStateMinutes, msg.Args{"minutes": max(left, 1)})
}

// tickAccess runs on each poll: access ends when its time is up or the
// agent connection that opened it is gone, and the open screen follows.
func (u *UI) tickAccess() {
	a := &u.access
	changed := false
	if a.on && (!u.b.GrantHeld() || (!a.until.IsZero() && !time.Now().Before(a.until))) {
		a.on = false
		u.closeApprovals()
		changed = true
	}
	if u.screen != screenAccess {
		return
	}
	switch {
	case changed:
		u.renderAccess()
	case a.status != nil:
		a.status.Segments[0].(*widget.TextSegment).Text = u.accessText()
		a.status.Refresh()
	}
	u.fetchActivity()
}

// fetchActivity reads the activity list, at most every activityEvery.
func (u *UI) fetchActivity() {
	a := &u.access
	if a.fetching || time.Since(a.fetched) < activityEvery {
		return
	}
	a.fetching, a.fetched = true, time.Now()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), accessTimeout)
		defer cancel()
		e, err := u.b.Activity(ctx)
		fyne.Do(func() {
			a.fetching = false
			if err != nil || slices.EqualFunc(e, a.entries, sameEntry) {
				return
			}
			a.entries = e
			if u.screen == screenAccess {
				u.renderAccess()
			}
		})
	}()
}

func sameEntry(a, b ipc.ActivityEntry) bool {
	return a.Time.Equal(b.Time) && a.Client == b.Client && a.Tool == b.Tool && a.Summary == b.Summary && a.Result == b.Result
}

func (u *UI) turnOn() {
	a := &u.access
	if a.working || a.on {
		return
	}
	g := ipc.AssistGrant{Minutes: accessDurations[a.choice].minutes, Groups: []string{}}
	for _, ag := range accessGroups {
		if !a.unchecked[ag.group] {
			g.Groups = append(g.Groups, ag.group)
		}
	}
	a.working = true
	u.renderAccess()
	start := time.Now() // before the daemon's clock starts: never shows more time than there is
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), accessTimeout)
		defer cancel()
		err := u.b.Grant(ctx, g)
		if err != nil {
			// The daemon may have stored the grant all the same (a
			// timeout after it took it): close it, so that access the app
			// shows as off is off.
			rctx, rcancel := context.WithTimeout(context.Background(), accessTimeout)
			u.b.Revoke(rctx)
			rcancel()
		}
		fyne.Do(func() {
			a.working = false
			if err != nil {
				u.setNotice(u.translate(err))
			} else {
				a.on, a.until = true, time.Time{}
				if g.Minutes > 0 {
					a.until = start.Add(time.Duration(g.Minutes) * time.Minute)
				}
			}
			if u.screen == screenAccess {
				u.renderAccess()
			}
		})
	}()
}

// turnOff closes access. The approval windows close at once, as refused;
// the daemon refuses what waits for them too.
func (u *UI) turnOff() {
	a := &u.access
	if a.working {
		return
	}
	u.closeApprovals()
	a.working = true
	u.renderAccess()
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), accessTimeout)
		defer cancel()
		err := u.b.Revoke(ctx)
		fyne.Do(func() {
			a.working = false
			if err != nil {
				u.setNotice(u.translate(err))
			} else {
				a.on = false
			}
			if u.screen == screenAccess {
				u.renderAccess()
			}
		})
	}()
}

func (u *UI) renderAccess() {
	a := &u.access
	a.status = rich(u.accessText(), "", "", fyne.TextStyle{Bold: true})
	rows := []fyne.CanvasObject{h1(u.t(msg.UIAccessNav)), body(u.t(msg.UIAccessIntro)), a.status}
	if a.on {
		for _, ag := range accessGroups {
			if !a.unchecked[ag.group] {
				rows = append(rows, small(u.t(ag.label)))
			}
		}
		off := widget.NewButton(u.t(msg.UIAccessTurnOff), u.turnOff)
		if a.working {
			off.Disable()
		}
		rows = append(rows, container.NewHBox(off, layout.NewSpacer()))
	} else {
		rows = append(rows, u.accessForm()...)
	}

	path := latchwirePath()
	rows = append(rows, section(u.t(msg.UIAccessSetup)),
		label(u.t(msg.UIAccessClaudeCode)), u.copyField(claudeCommand(path), true),
		label(u.t(msg.UIAccessClaudeDesktop)), u.copyField(desktopConfig(path), true),
		label(u.t(msg.UIAccessOther)), u.copyField(shellQuote(path)+" mcp", true))

	rows = append(rows, section(u.t(msg.UIAccessActivity)))
	shown := 0
	for _, e := range a.entries {
		if e.Result == "checked" || shown == 20 {
			continue
		}
		shown++
		rows = append(rows, u.activityRow(e))
	}
	if shown == 0 {
		rows = append(rows, small(u.t(msg.UIAccessNoActivity)))
	}
	u.setMain(page(container.NewVScroll(container.NewVBox(rows...))))
	u.fetchActivity()
}

// accessForm is the duration and the groups to turn access on with.
func (u *UI) accessForm() []fyne.CanvasObject {
	a := &u.access
	var names []string
	for _, d := range accessDurations {
		names = append(names, u.t(d.label))
	}
	sel := widget.NewSelect(names, nil)
	sel.SetSelectedIndex(a.choice)
	sel.OnChanged = func(string) {
		if i := sel.SelectedIndex(); i >= 0 {
			a.choice = i
		}
	}
	rows := []fyne.CanvasObject{section(u.t(msg.UIAccessDuration)), sel, section(u.t(msg.UIAccessGroups))}
	for _, ag := range accessGroups {
		group := ag.group
		c := widget.NewCheck(u.t(ag.label), func(on bool) { a.unchecked[group] = !on })
		c.SetChecked(!a.unchecked[group])
		rows = append(rows, c)
	}
	on := widget.NewButton(u.t(msg.UIAccessTurnOn), u.turnOn)
	on.Importance = widget.HighImportance
	if a.working {
		on.Disable()
	}
	return append(rows, container.NewHBox(on, layout.NewSpacer()))
}

// activityResults names the results of the activity list.
var activityResults = map[string]msg.ID{
	"done":            msg.UIAccessResultDone,
	ipc.CodeDenied:    msg.UIAccessResultDenied,
	ipc.CodeAccessOff: msg.UIAccessResultOff,
	ipc.CodeNoApp:     msg.UIAccessResultNoApp,
	ipc.CodeCancelled: msg.UIAccessResultCancelled,
}

func (u *UI) activityRow(e ipc.ActivityEntry) fyne.CanvasObject {
	result := e.Result
	if id, ok := activityResults[result]; ok {
		result = u.t(id)
	} else if strings.HasPrefix(result, "error") {
		result = u.t(msg.UIAccessResultError)
	}
	text := []fyne.CanvasObject{strong(e.Tool + " · " + e.Client)}
	if e.Summary != "" {
		text = append(text, small(msg.Translate(u.lang, e.Summary)))
	}
	text = append(text, small(e.Time.Local().Format("15:04:05")+" · "+result))
	return card(container.NewVBox(text...))
}
