package ui

import (
	"io"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/storage"
	"github.com/ncruces/zenity"

	"github.com/Kodviva/latchwire/internal/msg"
)

// picker asks the user for a file and returns its path. A cancelled
// dialog is ("", nil).
type picker func(title string) (path string, err error)

// nativePicker is the operating system's own open dialog.
var nativePicker picker = func(title string) (string, error) {
	p, err := zenity.SelectFile(
		zenity.Title(title),
		zenity.FileFilters{{Name: ".conf", Patterns: []string{"*.conf"}, CaseFold: true}},
	)
	if err == zenity.ErrCanceled {
		return "", nil
	}
	return p, err
}

// pickConf opens the system picker and falls back to Fyne's own dialog
// when that is not available.
func (u *UI) pickConf() {
	pick := u.pick
	if pick == nil {
		pick = nativePicker
	}
	title := u.t(msg.UIImportConf)
	go func() {
		path, err := pick(title)
		fyne.Do(func() {
			switch {
			case err != nil:
				u.pickConfFyne()
			case path != "":
				u.openConfPath(path)
			}
		})
	}()
}

func (u *UI) openConfPath(path string) {
	r, err := storage.OpenFileFromURI(storage.NewFileURI(path))
	if err != nil {
		u.setNotice(u.translate(err))
		return
	}
	defer r.Close()
	u.readConf(r.URI().Name(), r)
}

func (u *UI) pickConfFyne() {
	d := dialog.NewFileOpen(func(r fyne.URIReadCloser, err error) {
		if err != nil {
			u.setNotice(u.translate(err))
			return
		}
		if r == nil {
			return
		}
		defer r.Close()
		u.readConf(r.URI().Name(), r)
	}, u.win)
	d.SetFilter(storage.NewExtensionFileFilter([]string{".conf"}))
	d.Show()
}

// dropped imports the first .conf file dropped on the window. Only the
// public key screen takes drops, and only while no form or dialog is open
// over it.
func (u *UI) dropped(uris []fyne.URI) {
	if u.screen != screenPubkey || len(uris) == 0 || u.win.Canvas().Overlays().Top() != nil {
		return
	}
	for _, uri := range uris {
		if strings.EqualFold(uri.Extension(), ".conf") {
			u.openConfPath(uri.Path())
			return
		}
	}
	u.setNotice(u.t(msg.UIDropNotConf))
}

// readConf reads a configuration within the size limit and hands it to
// importConf. The bytes may hold a preshared key, so they are wiped after.
func (u *UI) readConf(name string, r io.Reader) {
	data, err := io.ReadAll(io.LimitReader(r, maxConfBytes+1))
	defer clear(data)
	if err != nil {
		u.setNotice(u.translate(err))
		return
	}
	if len(data) > maxConfBytes {
		u.setNotice(u.tr("ConfigTooLargeFmt", msg.Args{"limit": maxConfBytes}))
		return
	}
	u.importConf(name, data)
}
