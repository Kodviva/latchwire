package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"

	"github.com/Kodviva/latchwire/desktop/assets"
)

// Colors of the concept board (spec §6).
var (
	colBackground = rgb(0x0E, 0x11, 0x16)
	colPanel      = rgb(0x13, 0x18, 0x20)
	colRaised     = rgb(0x1B, 0x22, 0x2C)
	colSidebar    = rgb(0x10, 0x14, 0x1A)
	colBorder     = rgb(0x2A, 0x31, 0x3C)
	colControl    = rgb(0x3A, 0x46, 0x56)
	colText       = rgb(0xE6, 0xED, 0xF3)
	colSecondary  = rgb(0xB4, 0xBE, 0xC9)
	colMuted      = rgb(0x9B, 0xA7, 0xB4)
	colAmber      = rgb(0xF2, 0xB5, 0x44)
	colWarnBg     = rgb(0x24, 0x1E, 0x10)
	colWarnText   = rgb(0xE8, 0xD9, 0xB0)
	colOnAmber    = rgb(0x11, 0x11, 0x11)
)

func rgb(r, g, b uint8) color.NRGBA { return color.NRGBA{R: r, G: g, B: b, A: 0xFF} }

// Theme color names for rich text.
const (
	nameSecondary fyne.ThemeColorName = "lw.secondary"
	nameMuted     fyne.ThemeColorName = "lw.muted"
	nameAmber     fyne.ThemeColorName = "lw.amber"
	nameWarnText  fyne.ThemeColorName = "lw.warnText"

	sizeH1    fyne.ThemeSizeName = "lw.h1"
	sizeH2    fyne.ThemeSizeName = "lw.h2"
	sizeSmall fyne.ThemeSizeName = "lw.small"
	sizeTiny  fyne.ThemeSizeName = "lw.tiny"
)

// styleHeading selects Space Grotesk. Fyne picks a font by style only, so the
// one combination the app has no other use for carries the heading font.
var styleHeading = fyne.TextStyle{Bold: true, Italic: true}

type latchTheme struct {
	regular, semibold, heading, mono fyne.Resource
}

func newTheme() fyne.Theme {
	return &latchTheme{
		regular:  fyne.NewStaticResource("Inter-Regular.ttf", assets.InterRegular),
		semibold: fyne.NewStaticResource("Inter-SemiBold.ttf", assets.InterSemiBold),
		heading:  fyne.NewStaticResource("SpaceGrotesk-Bold.ttf", assets.SpaceGroteskBold),
		mono:     fyne.NewStaticResource("JetBrainsMono-Regular.ttf", assets.JetBrainsMono),
	}
}

func (t *latchTheme) Color(n fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch n {
	case nameSecondary:
		return colSecondary
	case nameMuted, theme.ColorNamePlaceHolder:
		return colMuted
	case nameAmber, theme.ColorNamePrimary, theme.ColorNameFocus, theme.ColorNameHyperlink, theme.ColorNameWarning:
		return colAmber
	case nameWarnText:
		return colWarnText
	case theme.ColorNameBackground, theme.ColorNameInputBackground:
		return colBackground
	case theme.ColorNameButton, theme.ColorNameMenuBackground, theme.ColorNameOverlayBackground, theme.ColorNameHeaderBackground:
		return colRaised
	case theme.ColorNameDisabledButton:
		return colPanel
	case theme.ColorNameDisabled:
		return rgb(0x6C, 0x77, 0x85)
	case theme.ColorNameForeground:
		return colText
	case theme.ColorNameForegroundOnPrimary, theme.ColorNameForegroundOnWarning:
		return colOnAmber
	case theme.ColorNameHover, theme.ColorNamePressed:
		return colBorder
	case theme.ColorNameInputBorder:
		return colControl
	case theme.ColorNameSeparator, theme.ColorNameScrollBar:
		return colBorder
	case theme.ColorNameSelection:
		return color.NRGBA{R: 0xF2, G: 0xB5, B: 0x44, A: 0x40}
	case theme.ColorNameShadow:
		return color.NRGBA{A: 0x80}
	case theme.ColorNameError:
		return colAmber
	}
	return theme.DefaultTheme().Color(n, theme.VariantDark)
}

func (t *latchTheme) Font(s fyne.TextStyle) fyne.Resource {
	switch {
	case s.Monospace:
		return t.mono
	case s.Bold && s.Italic:
		return t.heading
	case s.Bold:
		return t.semibold
	}
	return t.regular
}

func (t *latchTheme) Icon(n fyne.ThemeIconName) fyne.Resource { return theme.DefaultTheme().Icon(n) }

func (t *latchTheme) Size(n fyne.ThemeSizeName) float32 {
	switch n {
	case theme.SizeNameText:
		return 14
	case sizeH1:
		return 30
	case sizeH2:
		return 20
	case sizeSmall:
		return 13
	case sizeTiny:
		return 12
	case theme.SizeNameInputRadius, theme.SizeNameSelectionRadius:
		return 8
	}
	return theme.DefaultTheme().Size(n)
}
