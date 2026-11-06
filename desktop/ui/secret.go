package ui

import (
	"strings"
	"unicode/utf8"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/driver/desktop"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

// maxSecret bounds a field: a management key in hexadecimal is 64 characters.
const maxSecret = 64

// SecretField takes a PIN, a PUK or a management key. It exists because
// widget.Entry keeps its text in strings and in an undo history, neither of
// which can be erased. This field keeps one byte slice that Take hands over
// and wipes, draws only as many dots as there are characters, has no undo,
// and does not accept pasted text or give any back: it implements no
// Shortcutable, so the clipboard shortcuts never reach it.
type SecretField struct {
	widget.BaseWidget

	buf      [maxSecret * utf8.UTFMax]byte
	n        int
	focused  bool
	OnSubmit func()

	dots *canvas.Text
	box  *canvas.Rectangle
}

var (
	_ fyne.Focusable     = (*SecretField)(nil)
	_ fyne.Tappable      = (*SecretField)(nil)
	_ desktop.Cursorable = (*SecretField)(nil)
)

// NewSecretField returns an empty field.
func NewSecretField() *SecretField {
	f := &SecretField{}
	f.ExtendBaseWidget(f)
	return f
}

// Len is the number of bytes typed.
func (f *SecretField) Len() int { return f.n }

// Take returns a copy of the input for the caller to wipe, and wipes the
// field.
func (f *SecretField) Take() []byte {
	out := make([]byte, f.n)
	copy(out, f.buf[:f.n])
	f.Wipe()
	return out
}

// Wipe erases the input.
func (f *SecretField) Wipe() {
	clear(f.buf[:])
	f.n = 0
	f.redraw()
}

func (f *SecretField) redraw() {
	if f.dots == nil {
		return
	}
	f.dots.Text = strings.Repeat("•", utf8.RuneCount(f.buf[:f.n]))
	f.dots.Refresh()
}

// TypedRune adds a character. The rune stays out of any string.
func (f *SecretField) TypedRune(r rune) {
	if utf8.RuneCount(f.buf[:f.n]) >= maxSecret {
		return
	}
	f.n += utf8.EncodeRune(f.buf[f.n:], r)
	f.redraw()
}

// TypedKey handles editing keys.
func (f *SecretField) TypedKey(e *fyne.KeyEvent) {
	switch e.Name {
	case fyne.KeyBackspace, fyne.KeyDelete:
		if f.n > 0 {
			_, size := utf8.DecodeLastRune(f.buf[:f.n])
			clear(f.buf[f.n-size : f.n])
			f.n -= size
			f.redraw()
		}
	case fyne.KeyReturn, fyne.KeyEnter:
		if f.OnSubmit != nil {
			f.OnSubmit()
		}
	}
}

// Tapped takes the keyboard focus.
func (f *SecretField) Tapped(*fyne.PointEvent) {
	if c := fyne.CurrentApp().Driver().CanvasForObject(f); c != nil {
		c.Focus(f)
	}
}

// FocusGained marks the field.
func (f *SecretField) FocusGained() { f.focused = true; f.paint() }

// FocusLost unmarks the field.
func (f *SecretField) FocusLost() { f.focused = false; f.paint() }

// Cursor shows that the field takes text.
func (f *SecretField) Cursor() desktop.Cursor { return desktop.TextCursor }

func (f *SecretField) paint() {
	if f.box == nil {
		return
	}
	f.box.StrokeColor, f.box.StrokeWidth = colControl, 1
	if f.focused {
		f.box.StrokeColor, f.box.StrokeWidth = colAmber, 2
	}
	f.box.Refresh()
}

// MinSize keeps the height constant, full or empty.
func (f *SecretField) MinSize() fyne.Size { return fyne.NewSize(240, 44) }

// CreateRenderer implements fyne.Widget.
func (f *SecretField) CreateRenderer() fyne.WidgetRenderer {
	f.box = canvas.NewRectangle(colBackground)
	f.box.CornerRadius = 8
	f.dots = canvas.NewText("", colText)
	f.dots.TextSize = 16
	f.dots.TextStyle = fyne.TextStyle{Monospace: true}
	f.paint()
	f.redraw()
	return widget.NewSimpleRenderer(container.NewStack(f.box,
		container.New(layout.NewCustomPaddedLayout(10, 10, 12, 12), f.dots)))
}
