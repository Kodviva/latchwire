package ui

import (
	"net/url"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"

	"github.com/Kodviva/latchwire/internal/desktop"
	"github.com/Kodviva/latchwire/internal/msg"
)

// Where the links of this file lead. The Yubico link is the general product
// page: Latchwire names no seller and no model to buy.
const (
	siteURL   = "https://latchwire.com"
	yubicoURL = "https://www.yubico.com/products/"
)

// explorePages are the three short pages for people who are only looking:
// what Latchwire does, why the key cannot be copied, what it takes.
var explorePages = []struct{ title, text msg.ID }{
	{msg.UIExploreWhatTitle, msg.UIExploreWhat},
	{msg.UIExploreWhyTitle, msg.UIExploreWhy},
	{msg.UIExploreNeedTitle, msg.UIExploreNeed},
}

func (u *UI) renderExplore() {
	last := len(explorePages) - 1
	u.explorePage = min(max(u.explorePage, 0), last)
	p := explorePages[u.explorePage]
	rows := []fyne.CanvasObject{
		small(u.tr(msg.UIExplorePageFmt, msg.Args{"n": u.explorePage + 1, "total": len(explorePages)})),
		h1(u.t(p.title)),
		card(body(u.t(p.text))),
	}
	var nav []fyne.CanvasObject
	if u.explorePage > 0 {
		nav = append(nav, widget.NewButton(u.t(msg.UIExploreBack), func() { u.explorePage--; u.render() }))
	}
	nav = append(nav, layout.NewSpacer())
	if u.explorePage < last {
		next := widget.NewButton(u.t(msg.UIExploreNext), func() { u.explorePage++; u.render() })
		next.Importance = widget.HighImportance
		nav = append(nav, next)
	} else {
		site := widget.NewButton(u.t(msg.UIExploreSite), func() { u.openLink(siteURL) })
		site.Importance = widget.LowImportance
		ready := widget.NewButton(u.t(msg.UIExploreReady), func() {
			u.explorePage = 0
			u.draft, u.step = desktop.Survey{}, askWhy
			u.show(screenSurvey)
		})
		ready.Importance = widget.HighImportance
		nav = append(nav, site, ready)
	}
	rows = append(rows, container.NewHBox(nav...))
	u.setMain(page(container.NewVScroll(container.NewVBox(rows...))))
}

// openLink opens a fixed web address in the browser.
func (u *UI) openLink(raw string) {
	if l, err := url.Parse(raw); err == nil {
		_ = u.app.OpenURL(l)
	}
}

// waitCard sits above the roadmap of someone with no YubiKey: what to get,
// and the way to carry on once it is in hand.
func (u *UI) waitCard() fyne.CanvasObject {
	link := widget.NewButton(u.t(msg.UIRoadmapWaitLink), func() { u.openLink(yubicoURL) })
	have := widget.NewButton(u.t(msg.UIRoadmapWaitHave), func() {
		s := u.survey
		s.Card = desktop.CardPlugged
		u.saveSurvey(s)
		u.renderRoadmap()
	})
	have.Importance = widget.HighImportance
	return warnBox(container.NewVBox(
		strong(u.t(msg.UIRoadmapWaitTitle)),
		body(u.t(msg.UIRoadmapWait)),
		container.NewHBox(link, have)))
}
