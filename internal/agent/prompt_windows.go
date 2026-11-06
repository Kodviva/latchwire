package agent

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/msg"
)

// The Windows PIN dialog is a small window of its own: Windows has no dialog
// program like osascript or pinentry, and the credential dialogs in credui
// ask for a user name and cannot time out. It follows the rules of
// prompt.go that apply to a dialog in this process: the PIN stays in a fixed
// buffer that is wiped, and the window gives up by itself after
// dialogTimeout, which counts as cancelled.

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")

	procRegisterClassEx     = user32.NewProc("RegisterClassExW")
	procCreateWindowEx      = user32.NewProc("CreateWindowExW")
	procDestroyWindow       = user32.NewProc("DestroyWindow")
	procDefWindowProc       = user32.NewProc("DefWindowProcW")
	procGetMessage          = user32.NewProc("GetMessageW")
	procTranslateMessage    = user32.NewProc("TranslateMessage")
	procDispatchMessage     = user32.NewProc("DispatchMessageW")
	procIsDialogMessage     = user32.NewProc("IsDialogMessageW")
	procPostQuitMessage     = user32.NewProc("PostQuitMessage")
	procSetTimer            = user32.NewProc("SetTimer")
	procKillTimer           = user32.NewProc("KillTimer")
	procGetWindowText       = user32.NewProc("GetWindowTextW")
	procSetWindowText       = user32.NewProc("SetWindowTextW")
	procSendMessage         = user32.NewProc("SendMessageW")
	procSetForegroundWindow = user32.NewProc("SetForegroundWindow")
	procSetFocus            = user32.NewProc("SetFocus")
	procGetSystemMetrics    = user32.NewProc("GetSystemMetrics")
	procLoadCursor          = user32.NewProc("LoadCursorW")
	procMessageBox          = user32.NewProc("MessageBoxW")
	procGetModuleHandle     = kernel32.NewProc("GetModuleHandleW")
	procGetStockObject      = gdi32.NewProc("GetStockObject")
)

// Win32 values (winuser.h, wingdi.h).
const (
	wsOverlapped  = 0x00000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsVisible     = 0x10000000
	wsChild       = 0x40000000
	wsTabStop     = 0x00010000
	wsExTopmost   = 0x00000008
	wsExDlgFrame  = 0x00000001
	wsExClient    = 0x00000200
	esPassword    = 0x0020
	esAutoHScroll = 0x0080
	bsPushButton  = 0x0000
	bsDefPush     = 0x0001

	wmDestroy    = 0x0002
	wmClose      = 0x0010
	wmCommand    = 0x0111
	wmTimer      = 0x0113
	wmSetFont    = 0x0030
	emSetLimit   = 0x00C5
	colorBtnFace = 15
	idcArrow     = 32512
	smCxScreen   = 0
	smCyScreen   = 1
	defaultFont  = 17 // DEFAULT_GUI_FONT

	idOK     = 1
	idCancel = 2
	idEdit   = 100
	timerID  = 1

	mbOK          = 0x0
	mbIconWarning = 0x30
	mbSetFg       = 0x00010000
	mbTopmost     = 0x00040000

	// maxPINChars bounds the edit box; a PIV PIN has at most 8.
	maxPINChars = 64
)

type wndClassEx struct {
	size       uint32
	style      uint32
	wndProc    uintptr
	clsExtra   int32
	wndExtra   int32
	instance   windows.Handle
	icon       windows.Handle
	cursor     windows.Handle
	background windows.Handle
	menuName   *uint16
	className  *uint16
	iconSm     windows.Handle
}

type winMsg struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	ptX     int32
	ptY     int32
	private uint32
}

// pinWindow is the state of the one dialog that can be open: the window
// procedure has no way to carry a pointer that is simpler than this, and
// the agent asks for one PIN at a time.
var pinWindow struct {
	sync.Mutex
	edit    uintptr
	buf     [maxPINChars + 1]uint16
	n       int
	entered bool
	timeout bool
}

var (
	classOnce sync.Once
	classErr  error
	className = windows.StringToUTF16Ptr("LatchwirePIN")
)

func registerClass() error {
	classOnce.Do(func() {
		inst, _, _ := procGetModuleHandle.Call(0)
		cur, _, _ := procLoadCursor.Call(0, idcArrow)
		c := wndClassEx{
			wndProc:    windows.NewCallback(pinProc),
			instance:   windows.Handle(inst),
			cursor:     windows.Handle(cur),
			background: colorBtnFace + 1,
			className:  className,
		}
		c.size = uint32(unsafe.Sizeof(c))
		if r, _, e := procRegisterClassEx.Call(uintptr(unsafe.Pointer(&c))); r == 0 {
			classErr = e
		}
	})
	return classErr
}

func pinProc(hwnd uintptr, m uint32, wParam, lParam uintptr) uintptr {
	switch m {
	case wmCommand:
		switch wParam & 0xffff {
		case idOK:
			w := &pinWindow
			n, _, _ := procGetWindowText.Call(w.edit, uintptr(unsafe.Pointer(&w.buf[0])), maxPINChars+1)
			w.n, w.entered = int(n), true
			wipeEdit(w.edit)
			procDestroyWindow.Call(hwnd)
		case idCancel:
			wipeEdit(pinWindow.edit)
			procDestroyWindow.Call(hwnd)
		}
		return 0
	case wmTimer:
		pinWindow.timeout = true
		wipeEdit(pinWindow.edit)
		procDestroyWindow.Call(hwnd)
		return 0
	case wmClose:
		wipeEdit(pinWindow.edit)
		procDestroyWindow.Call(hwnd)
		return 0
	case wmDestroy:
		procKillTimer.Call(hwnd, timerID)
		procPostQuitMessage.Call(0)
		return 0
	}
	r, _, _ := procDefWindowProc.Call(hwnd, uintptr(m), wParam, lParam)
	return r
}

// wipeEdit clears the PIN from the edit control's own buffer.
func wipeEdit(edit uintptr) {
	var empty uint16
	procSetWindowText.Call(edit, uintptr(unsafe.Pointer(&empty)))
}

func child(class string, text *uint16, style uintptr, x, y, w, h int, parent, id uintptr, exStyle uintptr, font uintptr) uintptr {
	hwnd, _, _ := procCreateWindowEx.Call(exStyle, uintptr(unsafe.Pointer(windows.StringToUTF16Ptr(class))), uintptr(unsafe.Pointer(text)),
		wsChild|wsVisible|style, uintptr(x), uintptr(y), uintptr(w), uintptr(h), parent, id, 0, 0)
	if hwnd != 0 {
		procSendMessage.Call(hwnd, wmSetFont, font, 1)
	}
	return hwnd
}

// askPIN shows the window and runs its message loop on this thread, as
// Windows requires. entered is false when the user cancelled or the time
// ran out.
func askPIN(text, title string, millis uint32) (pin string, entered bool, err error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	w := &pinWindow
	w.Lock()
	defer w.Unlock()
	w.entered, w.timeout, w.n = false, false, 0
	defer func() { clear(w.buf[:]) }()
	if err := registerClass(); err != nil {
		return "", false, err
	}
	const width, height = 420, 220
	sx, _, _ := procGetSystemMetrics.Call(smCxScreen)
	sy, _, _ := procGetSystemMetrics.Call(smCyScreen)
	titleW, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return "", false, err
	}
	hwnd, _, e := procCreateWindowEx.Call(wsExTopmost|wsExDlgFrame, uintptr(unsafe.Pointer(className)), uintptr(unsafe.Pointer(titleW)),
		wsOverlapped|wsCaption|wsSysMenu|wsVisible, (sx-width)/2, (sy-height)/2, width, height, 0, 0, 0, 0)
	if hwnd == 0 {
		return "", false, e
	}
	font, _, _ := procGetStockObject.Call(defaultFont)
	// Windows controls end lines with CR LF.
	body, err := windows.UTF16PtrFromString(strings.ReplaceAll(text, "\n", "\r\n"))
	if err != nil {
		procDestroyWindow.Call(hwnd)
		return "", false, err
	}
	child("STATIC", body, 0, 16, 12, 372, 100, hwnd, 0, 0, font)
	w.edit = child("EDIT", nil, wsTabStop|esPassword|esAutoHScroll, 16, 116, 372, 24, hwnd, idEdit, wsExClient, font)
	procSendMessage.Call(w.edit, emSetLimit, maxPINChars, 0)
	child("BUTTON", windows.StringToUTF16Ptr(msg.AgentPINDialogOK), wsTabStop|bsDefPush, 212, 150, 84, 26, hwnd, idOK, 0, font)
	child("BUTTON", windows.StringToUTF16Ptr(msg.AgentPINDialogCancel), wsTabStop|bsPushButton, 304, 150, 84, 26, hwnd, idCancel, 0, font)
	procSetForegroundWindow.Call(hwnd)
	procSetFocus.Call(w.edit)
	procSetTimer.Call(hwnd, timerID, uintptr(millis), 0)

	var m winMsg
	for {
		r, _, _ := procGetMessage.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if r == 0 || int32(r) == -1 {
			break
		}
		// Enter, Escape and Tab behave as in a dialog.
		if d, _, _ := procIsDialogMessage.Call(hwnd, uintptr(unsafe.Pointer(&m))); d != 0 {
			continue
		}
		procTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		procDispatchMessage.Call(uintptr(unsafe.Pointer(&m)))
	}
	if !w.entered {
		return "", false, nil
	}
	return windows.UTF16ToString(w.buf[:w.n]), true, nil
}

// windowsPrompter asks for the PIN in a window.
type windowsPrompter struct{}

// newGUIPrompter asks for the PIN in a window.
func newGUIPrompter() Prompter { return windowsPrompter{} }

func (windowsPrompter) PIN(d keyprovider.Description, retriesLeft int) (string, error) {
	pin, ok, err := askPIN(dialogText(d, retriesLeft), msg.AgentPINDialogTitle, uint32(dialogTimeout.Milliseconds()))
	switch {
	case err != nil:
		return "", fmt.Errorf("%s: %w", msg.AgentPINDialogFailed, err)
	case !ok:
		return "", keyprovider.ErrPINRequired
	}
	return pin, nil
}

// Warn logs m and shows it, since a dialog user does not see the log. The
// box is not waited for: nothing in the agent may stall behind it.
func (windowsPrompter) Warn(m string) {
	log.Print(m)
	go func() {
		text, err := syscall.UTF16PtrFromString(m)
		if err != nil {
			return
		}
		title, err := syscall.UTF16PtrFromString(msg.AgentPINDialogTitle)
		if err != nil {
			return
		}
		if r, _, e := procMessageBox.Call(0, uintptr(unsafe.Pointer(text)), uintptr(unsafe.Pointer(title)), mbOK|mbIconWarning|mbSetFg|mbTopmost); r == 0 {
			log.Printf("%s: %v", msg.AgentNotifyFailed, e)
		}
	}()
}
