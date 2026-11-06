package ui

import (
	"image/color"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// rich returns wrapping text in a theme color and size.
func rich(s string, c fyne.ThemeColorName, size fyne.ThemeSizeName, style fyne.TextStyle) *widget.RichText {
	r := widget.NewRichText(&widget.TextSegment{Text: s, Style: widget.RichTextStyle{
		ColorName: c, SizeName: size, TextStyle: style,
	}})
	r.Wrapping = fyne.TextWrapWord
	return r
}

func h1(s string) fyne.CanvasObject { return rich(s, "", sizeH1, styleHeading) }
func h2(s string) fyne.CanvasObject { return rich(s, "", sizeH2, styleHeading) }
func body(s string) fyne.CanvasObject {
	return rich(s, nameSecondary, "", fyne.TextStyle{})
}
func small(s string) fyne.CanvasObject {
	return rich(s, nameMuted, sizeSmall, fyne.TextStyle{})
}
func label(s string) fyne.CanvasObject {
	return rich(s, nameMuted, sizeSmall, fyne.TextStyle{})
}
func strong(s string) fyne.CanvasObject {
	return rich(s, "", "", fyne.TextStyle{Bold: true})
}
func eyebrow(s string) fyne.CanvasObject {
	return rich(s, nameAmber, sizeTiny, fyne.TextStyle{Monospace: true})
}
func section(s string) fyne.CanvasObject {
	return rich(s, nameMuted, sizeTiny, fyne.TextStyle{Bold: true})
}

// mono is selectable-looking code text: a public key or a [Peer] block.
func mono(s string) fyne.CanvasObject {
	r := rich(s, nameSecondary, sizeSmall, fyne.TextStyle{Monospace: true})
	r.Wrapping = fyne.TextWrapBreak
	return r
}

// panel draws content on a rounded box.
func panel(fill, border color.Color, strokeW float32, pad float32, content fyne.CanvasObject) fyne.CanvasObject {
	r := canvas.NewRectangle(fill)
	r.CornerRadius = 12
	r.StrokeColor = border
	r.StrokeWidth = strokeW
	return container.NewStack(r, container.New(layout.NewCustomPaddedLayout(pad, pad, pad, pad), content))
}

func card(content fyne.CanvasObject) fyne.CanvasObject {
	return panel(colPanel, colBorder, 1, 14, content)
}

func warnBox(content fyne.CanvasObject) fyne.CanvasObject {
	return panel(colWarnBg, colAmber, 1, 14, content)
}

func warnText(s string) fyne.CanvasObject {
	return rich(s, nameWarnText, "", fyne.TextStyle{})
}

// pill is a rounded status label.
func pill(s string, lit bool) fyne.CanvasObject {
	bg, fg := color.Color(colRaised), color.Color(colSecondary)
	if lit {
		bg, fg = colAmber, colOnAmber
	}
	r := canvas.NewRectangle(bg)
	r.CornerRadius = 99
	t := canvas.NewText(s, fg)
	t.TextSize = 13
	t.TextStyle = fyne.TextStyle{Bold: true}
	return container.NewStack(r, container.New(layout.NewCustomPaddedLayout(6, 6, 12, 12), t))
}

// dot is the state mark of a tunnel in the sidebar.
func dot(lit bool) fyne.CanvasObject {
	c := canvas.NewCircle(color.Transparent)
	if lit {
		c.FillColor = colAmber
	} else {
		c.StrokeColor = rgb(0x6C, 0x77, 0x85)
		c.StrokeWidth = 2
	}
	return container.NewGridWrap(fyne.NewSize(10, 10), c)
}

// splitLayout gives the last object a fixed width and the first the rest.
type splitLayout struct {
	right, gap float32
}

func (l splitLayout) Layout(o []fyne.CanvasObject, s fyne.Size) {
	left := s.Width - l.right - l.gap
	o[0].Move(fyne.NewPos(0, 0))
	o[0].Resize(fyne.NewSize(left, s.Height))
	o[1].Move(fyne.NewPos(left+l.gap, 0))
	o[1].Resize(fyne.NewSize(l.right, s.Height))
}

func (l splitLayout) MinSize(o []fyne.CanvasObject) fyne.Size {
	a, b := o[0].MinSize(), o[1].MinSize()
	return fyne.NewSize(a.Width+l.gap+l.right, max(a.Height, b.Height))
}

func split(right, gap float32, a, b fyne.CanvasObject) fyne.CanvasObject {
	return container.New(splitLayout{right, gap}, a, b)
}

// tapCard is a selectable box: a YubiKey in a list, a tunnel in the sidebar.
type tapCard struct {
	widget.BaseWidget
	content  fyne.CanvasObject
	selected bool
	onTap    func()
	hovered  bool
	bg       *canvas.Rectangle
	flat     bool // sidebar entry: no border
}

var (
	_ fyne.Tappable     = (*tapCard)(nil)
	_ desktop.Hoverable = (*tapCard)(nil)
)

func newTapCard(content fyne.CanvasObject, selected, flat bool, onTap func()) *tapCard {
	c := &tapCard{content: content, selected: selected, onTap: onTap, flat: flat}
	c.ExtendBaseWidget(c)
	return c
}

func (c *tapCard) Tapped(*fyne.PointEvent) {
	if c.onTap != nil {
		c.onTap()
	}
}

func (c *tapCard) MouseIn(*desktop.MouseEvent)    { c.hovered = true; c.paint() }
func (c *tapCard) MouseMoved(*desktop.MouseEvent) {}
func (c *tapCard) MouseOut()                      { c.hovered = false; c.paint() }

func (c *tapCard) paint() {
	if c.bg == nil {
		return
	}
	switch {
	case c.selected:
		c.bg.FillColor, c.bg.StrokeColor = colRaised, colAmber
	case c.hovered:
		c.bg.FillColor, c.bg.StrokeColor = colRaised, colBorder
	default:
		c.bg.FillColor, c.bg.StrokeColor = colPanel, colBorder
	}
	c.bg.StrokeWidth = 1
	if c.selected {
		c.bg.StrokeWidth = 2
	}
	if c.flat {
		c.bg.StrokeWidth = 0
		if !c.selected && !c.hovered {
			c.bg.FillColor = color.Transparent
		}
	}
	c.bg.Refresh()
}

func (c *tapCard) CreateRenderer() fyne.WidgetRenderer {
	c.bg = canvas.NewRectangle(colPanel)
	c.bg.CornerRadius = 10
	c.paint()
	pad := float32(14)
	if c.flat {
		pad = 10
	}
	return widget.NewSimpleRenderer(container.NewStack(c.bg,
		container.New(layout.NewCustomPaddedLayout(pad, pad, pad, pad), c.content)))
}

// modal shows content as a modal of the given width. RichText only knows its
// height once it has a width, and a form taller than the window scrolls.
func modal(win fyne.Window, width float32, content fyne.CanvasObject) *widget.PopUp {
	padded := container.New(layout.NewCustomPaddedLayout(16, 16, 16, 16), content)
	padded.Resize(fyne.NewSize(width, 10))
	h := padded.MinSize().Height
	var body fyne.CanvasObject = padded
	if limit := win.Canvas().Size().Height - 48; limit > 0 && h > limit {
		h = limit
		body = container.NewVScroll(padded)
	}
	return widget.NewModalPopUp(container.NewGridWrap(fyne.NewSize(width, h), body), win.Canvas())
}

// reflow undoes the terminal line breaks of a CLI text, keeping the breaks
// that end a sentence or a list item.
func reflow(s string) string {
	lines := strings.Split(s, "\n")
	var b strings.Builder
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if i > 0 {
			prev := strings.TrimSpace(lines[i-1])
			if strings.HasSuffix(prev, ".") || strings.HasSuffix(prev, ":") || strings.HasSuffix(prev, ",") {
				b.WriteByte('\n')
			} else {
				b.WriteByte(' ')
			}
		}
		b.WriteString(l)
	}
	return b.String()
}
