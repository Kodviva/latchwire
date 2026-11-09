// Package ui is the Fyne shell of the desktop app: a window with the three
// screens of spec §6 and a tray menu. It draws what internal/desktop decides.
package ui

import (
	"context"
	"os"
	"slices"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	fdesktop "fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/lang"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/desktop/assets"
	"github.com/Kodviva/latchwire/internal/daemon"
	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// pollEvery paces the status and card polling. The agent reports a removed
// card within a second, so the screen follows within about three.
const pollEvery = 2 * time.Second

const (
	prefLang     = "lang"
	prefSurvey   = "guide.survey"
	prefProgress = "guide.progress"
)

// Backend is what the shell needs from the outside world. *desktop.Client
// and desktop.Cards provide it in production, package demo in the demo build.
type Backend interface {
	Devices() ([]desktop.Device, error)
	Inspect(serial uint32) (desktop.CardInfo, error)
	Keygen(serial uint32, slot uint8, a desktop.Asker) (desktop.Key, error)
	Status(ctx context.Context) ([]ipc.TunnelStatus, error)
	Connect(ctx context.Context, name string) (ipc.TunnelStatus, error)
	Disconnect(ctx context.Context, name string) error
	Add(ctx context.Context, name, config string) error
}

// DemoAction is an extra button of the demo build.
type DemoAction struct {
	Label string
	Run   func()
}

// Options configures the shell.
type Options struct {
	Backend Backend
	// Demo marks the build as a demo; Actions are its buttons.
	Demo    bool
	Actions []DemoAction
	// Started runs in the background once the app is up.
	Started func()
}

type screen int

const (
	screenTunnels screen = iota
	screenOnboard
	screenPubkey
	screenSurvey
	screenRoadmap
	screenExplore
	screenGuide
	screenShare
)

// UI is the app. Its fields are touched on the Fyne goroutine only.
type UI struct {
	app  fyne.App
	win  fyne.Window
	opts Options
	b    Backend
	lang string

	root    *fyne.Container
	sidebar *fyne.Container
	notices *fyne.Container
	main    *fyne.Container
	// cancelForm closes the open secret form, if any.
	cancelForm func()

	screen   screen
	selected string // tunnel shown
	notice   string
	pick     picker // the file picker; nil means the system's

	statuses  []ipc.TunnelStatus
	devices   []desktop.Device
	infos     map[uint32]desktop.CardInfo
	daemonErr string
	pending   map[string]bool // tunnels with a call under way
	shownView *desktop.TunnelView
	trayKey   string

	card    onboardState
	session pubkeyState

	// survey holds the stored answers; its Help is empty until there are
	// some. known is set by the first successful reading of the daemon, asked
	// once the survey was shown. draft and step are the survey under way.
	survey   desktop.Survey
	progress desktop.Progress
	known    bool
	asked    bool
	// reask is set at launch for someone who stopped on the explore pages:
	// with no tunnel, they get the survey again.
	reask       bool
	draft       desktop.Survey
	step        int
	explorePage int
	// guideOpen is set once a hints user opened the server guide's steps.
	guideOpen bool
}

// New creates the app. Call Run to start it.
func New(a fyne.App, o Options) *UI {
	a.Settings().SetTheme(newTheme())
	u := &UI{app: a, opts: o, b: o.Backend, infos: map[uint32]desktop.CardInfo{}, pending: map[string]bool{}}
	u.lang = chooseLanguage(a)
	u.loadGuide()
	u.win = a.NewWindow("Latchwire")
	u.win.Resize(fyne.NewSize(1000, 680))
	u.win.SetOnDropped(func(_ fyne.Position, uris []fyne.URI) { u.dropped(uris) })
	u.win.SetCloseIntercept(func() { u.win.Hide() })
	u.sidebar = container.NewStack()
	u.notices = container.NewVBox()
	u.main = container.NewStack()
	u.win.SetContent(u.layout())
	u.render()
	return u
}

func chooseLanguage(a fyne.App) string {
	if v := os.Getenv("LATCHWIRE_LANG"); v != "" {
		return msg.Match(v)
	}
	if v := a.Preferences().String(prefLang); v != "" {
		return msg.Match(v)
	}
	return msg.Match(lang.SystemLocale().LanguageString())
}

func (u *UI) layout() fyne.CanvasObject {
	bg := canvas.NewRectangle(colBackground)
	side := canvas.NewRectangle(colSidebar)
	left := container.NewStack(side, container.New(layout.NewCustomPaddedLayout(18, 14, 14, 14), u.sidebar))
	right := container.NewBorder(u.notices, nil, nil, nil, u.main)
	return container.NewStack(bg, container.New(leftFixed{240}, left, right))
}

// leftFixed gives the first object a fixed width.
type leftFixed struct{ w float32 }

func (l leftFixed) Layout(o []fyne.CanvasObject, s fyne.Size) {
	o[0].Move(fyne.NewPos(0, 0))
	o[0].Resize(fyne.NewSize(l.w, s.Height))
	o[1].Move(fyne.NewPos(l.w, 0))
	o[1].Resize(fyne.NewSize(s.Width-l.w, s.Height))
}

func (l leftFixed) MinSize(o []fyne.CanvasObject) fyne.Size {
	m := o[1].MinSize()
	return fyne.NewSize(l.w+m.Width, max(o[0].MinSize().Height, m.Height))
}

func (u *UI) t(id msg.ID) string              { return msg.Render(u.lang, id, nil) }
func (u *UI) tr(id msg.ID, a msg.Args) string { return msg.Render(u.lang, id, a) }
func (u *UI) translate(err error) string      { return msg.Translate(u.lang, err.Error()) }

// showWindow brings the window up, for example for a PIN prompt.
func (u *UI) showWindow() {
	u.win.Show()
	u.win.RequestFocus()
}

// Window is the main window; tests look into it.
func (u *UI) Window() fyne.Window { return u.win }

// Run shows the window and blocks until the app quits.
func (u *UI) Run(ctx context.Context) {
	u.setupTray()
	go u.poll(ctx)
	u.win.Show()
	if u.opts.Started != nil {
		go u.opts.Started()
	}
	u.app.Run()
}

func (u *UI) poll(ctx context.Context) {
	t := time.NewTicker(pollEvery)
	defer t.Stop()
	for {
		u.pollOnce(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (u *UI) pollOnce(ctx context.Context) {
	devs, _ := u.b.Devices()
	sts, err := u.b.Status(ctx)
	fyne.Do(func() { u.apply(devs, sts, err) })
}

// apply takes a fresh reading and redraws what changed.
func (u *UI) apply(devs []desktop.Device, sts []ipc.TunnelStatus, err error) {
	e := ""
	if err != nil {
		e = u.translate(err)
		sts = nil
	}
	changedDevices := !slices.Equal(devs, u.devices)
	changedTunnels := !slices.Equal(sts, u.statuses) || e != u.daemonErr
	u.devices, u.statuses, u.daemonErr = devs, sts, e
	u.known = u.known || err == nil
	u.decideFirstRun()
	u.markHandshake()
	if u.selected == "" && len(sts) > 0 {
		u.selected = sts[0].Name
	}
	if changedDevices {
		u.inspectNew()
	}
	u.renderNotices()
	switch u.screen {
	case screenTunnels:
		if changedTunnels || changedDevices {
			u.renderSidebar()
			u.renderTunnels(false)
		} else {
			u.renderTunnels(true) // the handshake age moves on
		}
	case screenOnboard:
		if changedDevices {
			u.renderOnboard()
		}
		if changedTunnels {
			u.renderSidebar()
		}
	case screenPubkey:
		if changedDevices {
			u.renderBackup()
		}
		if changedTunnels {
			u.renderSidebar()
		}
	default:
		if changedTunnels {
			u.renderSidebar()
		}
	}
	u.updateTray()
}

func (u *UI) render() {
	u.renderSidebar()
	u.renderNotices()
	switch u.screen {
	case screenTunnels:
		u.shownView = nil
		u.renderTunnels(false)
	case screenOnboard:
		u.renderOnboard()
	case screenPubkey:
		u.renderPubkey()
	case screenSurvey:
		u.renderSurvey()
	case screenRoadmap:
		u.renderRoadmap()
	case screenExplore:
		u.renderExplore()
	case screenGuide:
		u.renderGuide()
	case screenShare:
		u.renderShare()
	}
}

func (u *UI) show(s screen) {
	u.screen = s
	u.render()
}

func (u *UI) setMain(o fyne.CanvasObject) {
	u.main.Objects = []fyne.CanvasObject{o}
	u.main.Refresh()
}

func (u *UI) setNotice(s string) {
	u.notice = s
	u.renderNotices()
	u.app.SendNotification(fyne.NewNotification("Latchwire", s))
}

func (u *UI) renderNotices() {
	var rows []fyne.CanvasObject
	if u.opts.Demo {
		rows = append(rows, strip(warnText(u.t(msg.UIDemoBanner))))
	}
	if u.daemonErr != "" {
		rows = append(rows, strip(warnText(u.daemonErr)))
	}
	if u.notice != "" {
		x := widget.NewButtonWithIcon("", theme.CancelIcon(), func() { u.notice = ""; u.renderNotices() })
		x.Importance = widget.LowImportance
		rows = append(rows, strip(container.NewBorder(nil, nil, nil, x, warnText(u.notice))))
	}
	u.notices.Objects = rows
	u.notices.Refresh()
}

// strip is a notice row across the top of the main area.
func strip(o fyne.CanvasObject) fyne.CanvasObject {
	return container.New(layout.NewCustomPaddedLayout(12, 0, 24, 24), warnBox(o))
}

func (u *UI) renderSidebar() {
	var rows []fyne.CanvasObject
	if u.roadmapOpen() {
		row := container.NewBorder(nil, nil, nil, nil, strong(u.t(msg.UIRoadmapTitle)))
		rows = append(rows, newTapCard(row, u.screen == screenRoadmap, true, func() { u.show(screenRoadmap) }))
	}
	rows = append(rows, section(u.t(msg.UITunnelsHeader)))
	for _, st := range u.statuses {
		name := st.Name
		lit := st.State == daemon.StateConnected
		selected := u.screen == screenTunnels && name == u.selected
		row := container.NewBorder(nil, nil, nil, container.NewCenter(dot(lit)), strong(name))
		rows = append(rows, newTapCard(row, selected, true, func() {
			u.selected = name
			u.show(screenTunnels)
		}))
	}
	add := widget.NewButton(u.t(msg.UINewTunnel), func() { u.show(screenOnboard) })
	names, codes := languages()
	sel := widget.NewSelect(names, nil)
	if i := slices.Index(codes, u.lang); i >= 0 {
		sel.SetSelectedIndex(i)
	}
	sel.OnChanged = func(string) { u.setLanguage(codes[sel.SelectedIndex()]) }
	foot := container.NewVBox(add, widget.NewSeparator(), small(u.t(msg.UILanguage)), sel)
	if u.survey.Help != "" {
		foot.Add(u.helpSelect())
	}
	u.sidebar.Objects = []fyne.CanvasObject{container.NewBorder(container.NewVBox(rows...), foot, nil, nil)}
	u.sidebar.Refresh()
}

func languages() (names, codes []string) {
	for _, l := range msg.Supported() {
		codes = append(codes, l)
		names = append(names, msg.Render(l, msg.UILangName, nil))
	}
	return names, codes
}

func (u *UI) setLanguage(l string) {
	if l == u.lang {
		return
	}
	u.lang = l
	u.app.Preferences().SetString(prefLang, l)
	u.trayKey = ""
	u.render()
	u.updateTray()
}

func (u *UI) connectedCount() int {
	n := 0
	for _, st := range u.statuses {
		if st.State == daemon.StateConnected {
			n++
		}
	}
	return n
}

// setupTray installs the tray or menu bar item.
func (u *UI) setupTray() {
	if d, ok := u.app.(fdesktop.App); ok {
		d.SetSystemTrayIcon(theme.NewThemedResource(fyne.NewStaticResource("tray.svg", assets.TrayIcon)))
		u.updateTray()
	}
}

// trayMenu is the tray menu's content for the current state.
func (u *UI) trayMenu() *fyne.Menu {
	head := fyne.NewMenuItem(u.tr(msg.UITrayConnected, msg.Args{"count": u.connectedCount()}), nil)
	head.Disabled = true
	items := []*fyne.MenuItem{head}
	if len(u.statuses) == 0 {
		none := fyne.NewMenuItem(u.t(msg.UITrayNoTunnels), nil)
		none.Disabled = true
		items = append(items, none)
	}
	for _, st := range u.statuses {
		name := st.Name
		view := desktop.NewTunnelView(u.lang, st, u.present, time.Now())
		id := msg.UITrayDisconnect
		if view.Connects {
			id = msg.UITrayConnect
		}
		it := fyne.NewMenuItem(u.tr(id, msg.Args{"name": name}), func() { u.toggle(name, view.Connects) })
		it.Disabled = u.pending[name]
		items = append(items, it)
	}
	items = append(items, fyne.NewMenuItemSeparator(),
		fyne.NewMenuItem(u.t(msg.UITrayOpen), u.showWindow))
	quit := fyne.NewMenuItem(u.t(msg.UITrayQuit), u.askQuit)
	quit.IsQuit = true
	items = append(items, quit)
	return fyne.NewMenu("Latchwire", items...)
}

func (u *UI) updateTray() {
	d, ok := u.app.(fdesktop.App)
	if !ok {
		return
	}
	m := u.trayMenu()
	key := ""
	for _, it := range m.Items {
		key += it.Label + "\x00"
		if it.Disabled {
			key += "d"
		}
	}
	if key == u.trayKey {
		return
	}
	u.trayKey = key
	d.SetSystemTrayMenu(m)
}

// askQuit warns before the agent goes away under a connected tunnel: the
// daemon tears a tunnel down 10 seconds after its agent left.
func (u *UI) askQuit() {
	n := u.connectedCount()
	if n == 0 {
		u.app.Quit()
		return
	}
	u.showWindow()
	dlg := dialog.NewConfirm(u.t(msg.UIQuitTitle), u.tr(msg.UIQuitBody, msg.Args{"count": n}), func(yes bool) {
		if yes {
			u.app.Quit()
		}
	}, u.win)
	dlg.SetConfirmText(u.t(msg.UITrayQuit))
	dlg.SetDismissText(u.t(msg.UICancel))
	dlg.Show()
}

func (u *UI) present(serial uint32) bool {
	return slices.ContainsFunc(u.devices, func(d desktop.Device) bool { return d.Serial == serial })
}
