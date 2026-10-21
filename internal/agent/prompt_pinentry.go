package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/msg"
)

// pinentry PIN dialog (Linux), spoken to with the Assuan protocol on its
// stdin and stdout. This file has no build tag so that its tests run on
// every system; prompt_linux.go selects it.

// pinentryDirs and pinentryNames are where pinentry is looked for, in
// order: each name in turn, in each directory. PATH is never used.
var (
	pinentryDirs  = []string{"/usr/bin", "/bin", "/usr/local/bin"}
	pinentryNames = []string{"pinentry", "pinentry-gnome3", "pinentry-qt", "pinentry-curses"}
)

// pinentryPassEnv are the variables pinentry gets from the agent's
// environment: what it needs to reach the desktop session and pick a
// language. Nothing else is inherited (no LD_*, no PATH).
var pinentryPassEnv = []string{
	"DISPLAY", "WAYLAND_DISPLAY", "XAUTHORITY", "DBUS_SESSION_BUS_ADDRESS",
	"XDG_RUNTIME_DIR", "XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "HOME",
	"LANG", "LC_ALL", "LC_CTYPE", "LC_MESSAGES",
}

const (
	// maxAssuanLine is the longest line accepted or sent, newline included
	// (Assuan allows 1000 bytes; more is a broken peer).
	maxAssuanLine = 4 << 10
	// maxAssuanRead caps everything read from one pinentry.
	maxAssuanRead = 64 << 10
	// maxPINData caps the decoded PIN (a PIV PIN has at most 8 bytes).
	maxPINData = 256
)

// GnuPG error codes (the low 16 bits of an Assuan ERR code) that mean the
// user did not answer: cancelled, fully cancelled, timed out.
const (
	gpgErrTimeout       = 62
	gpgErrCanceled      = 99
	gpgErrFullyCanceled = 198
	gpgErrCodeMask      = 0xFFFF
)

// findPinentry returns the first executable pinentry in dirs, or "".
func findPinentry(dirs []string) string {
	for _, name := range pinentryNames {
		for _, d := range dirs {
			p := filepath.Join(d, name)
			if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() && fi.Mode().Perm()&0o111 != 0 {
				return p
			}
		}
	}
	return ""
}

// pinentryEnv is pinentry's whole environment: a PATH of the fixed
// directories (a pinentry wrapper script may run the real program) and the
// desktop session variables from getenv.
func pinentryEnv(getenv func(string) string) []string {
	env := []string{"PATH=" + strings.Join(pinentryDirs, ":")}
	for _, k := range pinentryPassEnv {
		if v := getenv(k); v != "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

type pinentryPrompter struct {
	find    func() string                                    // the pinentry path, "" if none
	command func(ctx context.Context, path string) *exec.Cmd // the child, its Env set
	timeout time.Duration                                    // the dialog's own timeout
	grace   time.Duration                                    // then the child is killed
}

func newPinentryPrompter() *pinentryPrompter {
	return &pinentryPrompter{
		find: func() string { return findPinentry(pinentryDirs) },
		command: func(ctx context.Context, path string) *exec.Cmd {
			c := exec.CommandContext(ctx, path)
			c.Env = pinentryEnv(os.Getenv)
			return c
		},
		timeout: dialogTimeout,
		grace:   childGrace,
	}
}

func (p *pinentryPrompter) PIN(d keyprovider.Description, retriesLeft int) (string, error) {
	// Looked up for every prompt, so installing pinentry needs no restart.
	path := p.find()
	if path == "" {
		// The agent logs the request's error, this reason included.
		return "", fmt.Errorf("%w: %s", keyprovider.ErrPINRequired, msg.AgentNoPinentry)
	}
	ctx, cancel := context.WithTimeout(context.Background(), p.timeout+p.grace)
	defer cancel()
	deadline, _ := ctx.Deadline()

	// Own pipes (not StdinPipe/StdoutPipe) so they take deadlines: a
	// grandchild holding them open cannot block the agent past ctx.
	inR, inW, err := os.Pipe()
	if err != nil {
		return "", err
	}
	defer inW.Close()
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		return "", err
	}
	defer outR.Close()
	stderr := newLimitBuffer(maxChildOutput)
	cmd := p.command(ctx, path)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, stderr
	cmd.WaitDelay = childWaitDelay
	err = cmd.Start()
	inR.Close()
	outW.Close()
	if err != nil {
		return "", fmt.Errorf("starting pinentry: %w", err)
	}
	// Not supported everywhere (Windows); ctx still kills the child there.
	_ = outR.SetReadDeadline(deadline)
	_ = inW.SetWriteDeadline(deadline)

	secs := max(1, int(p.timeout/time.Second))
	pin, err := pinentryConverse(outR, inW, msg.AgentPINDialogTitle, dialogText(d, retriesLeft), msg.AgentPINDialogPrompt, secs)
	defer clear(pin)
	// Before cancel below: pinentry outlived its own timeout (the read
	// deadline or ctx fired), so nobody answered.
	timedOut := errors.Is(err, os.ErrDeadlineExceeded) || ctx.Err() != nil
	inW.Close()
	if err == nil || errors.Is(err, keyprovider.ErrPINRequired) {
		// The conversation ended with BYE: let pinentry exit by itself,
		// but not for long.
		t := time.AfterFunc(childWaitDelay, cancel)
		defer t.Stop()
	} else {
		cancel()
	}
	cmd.Wait()
	if err != nil {
		if errors.Is(err, keyprovider.ErrPINRequired) {
			return "", err
		}
		if timedOut {
			// Killed; like an osascript dialog that gave up.
			return "", fmt.Errorf("%w: pinentry did not answer in time (%v)", keyprovider.ErrPINRequired, err)
		}
		if s := strings.TrimSpace(string(stderr.buf)); s != "" {
			return "", fmt.Errorf("%w (pinentry said: %s)", err, s)
		}
		return "", err
	}
	return string(pin), nil
}

// Warn logs m; pinentry has no non-blocking way to show it. The PIN dialog
// itself shows the attempts left and the last-retry warning.
func (p *pinentryPrompter) Warn(m string) { log.Print(m) }

// pinentryConverse runs one PIN request over an Assuan connection: r is
// pinentry's stdout, w its stdin. It returns the PIN, which the caller
// wipes. A cancelled or timed-out dialog is keyprovider.ErrPINRequired.
func pinentryConverse(r io.Reader, w io.Writer, title, desc, prompt string, timeoutSecs int) ([]byte, error) {
	lr := &lineReader{r: r}
	defer lr.wipe()
	if _, err := lr.response(); err != nil {
		return nil, fmt.Errorf("greeting: %w", err)
	}
	cmds := []struct {
		line     string
		optional bool // an ERR answer is ignored (old pinentry)
	}{
		{"SETTITLE " + assuanEscape(title), false},
		{"SETDESC " + assuanEscape(desc), false},
		{"SETPROMPT " + assuanEscape(prompt), false},
		{"SETTIMEOUT " + strconv.Itoa(timeoutSecs), true},
	}
	for _, c := range cmds {
		if err := assuanSend(w, c.line); err != nil {
			return nil, err
		}
		if _, err := lr.response(); err != nil {
			var ae *assuanError
			if c.optional && errors.As(err, &ae) {
				continue
			}
			return nil, err
		}
	}
	if err := assuanSend(w, "GETPIN"); err != nil {
		return nil, err
	}
	pin := make([]byte, 0, maxPINData)
	if err := lr.getpin(&pin); err != nil {
		clear(pin[:cap(pin)])
		var ae *assuanError
		if errors.As(err, &ae) {
			// The conversation is still in step: end it politely.
			assuanBye(lr, w)
			if ae.cancelled() {
				return nil, keyprovider.ErrPINRequired
			}
		}
		return nil, err
	}
	assuanBye(lr, w)
	return pin, nil
}

func assuanBye(lr *lineReader, w io.Writer) {
	if assuanSend(w, "BYE") == nil {
		lr.response()
	}
}

func assuanSend(w io.Writer, line string) error {
	if len(line)+1 > maxAssuanLine {
		return errors.New("pinentry: command too long")
	}
	_, err := io.WriteString(w, line+"\n")
	return err
}

// assuanEscape percent-escapes "%", CR, LF and the other control bytes.
func assuanEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' || c < 0x20 || c == 0x7f {
			fmt.Fprintf(&b, "%%%02X", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// assuanError is an ERR answer.
type assuanError struct {
	code uint64
	line string
}

func (e *assuanError) Error() string { return "pinentry: " + e.line }

func (e *assuanError) cancelled() bool {
	switch e.code & gpgErrCodeMask {
	case gpgErrCanceled, gpgErrFullyCanceled, gpgErrTimeout:
		return true
	}
	return false
}

func parseAssuanErr(line []byte) error {
	s := string(line)
	f := strings.Fields(s)
	if len(s) > 200 {
		s = s[:200]
	}
	if len(f) < 2 {
		return &assuanError{line: s}
	}
	code, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		return fmt.Errorf("pinentry: malformed answer %q", s)
	}
	return &assuanError{code: code, line: s}
}

// lineReader reads Assuan lines into a fixed buffer that wipe clears.
type lineReader struct {
	r     io.Reader
	buf   [maxAssuanLine]byte
	n     int // bytes in buf
	skip  int // length of the line returned last, newline included
	total int
}

func (l *lineReader) wipe() { clear(l.buf[:]) }

// readLine returns the next line without its newline; it is valid until
// the next call.
func (l *lineReader) readLine() ([]byte, error) {
	if l.skip > 0 {
		copy(l.buf[:], l.buf[l.skip:l.n])
		l.n -= l.skip
		clear(l.buf[l.n:])
		l.skip = 0
	}
	for {
		if i := bytes.IndexByte(l.buf[:l.n], '\n'); i >= 0 {
			l.skip = i + 1
			return l.buf[:i], nil
		}
		if l.n == len(l.buf) {
			return nil, errors.New("pinentry: line too long")
		}
		if l.total >= maxAssuanRead {
			return nil, errors.New("pinentry: too much output")
		}
		m, err := l.r.Read(l.buf[l.n:])
		l.n += m
		l.total += m
		if m == 0 && err != nil {
			if errors.Is(err, io.EOF) {
				err = io.ErrUnexpectedEOF
			}
			return nil, fmt.Errorf("pinentry: %w", err)
		}
	}
}

// isLine reports whether line is the word kw alone or followed by a space.
func isLine(line []byte, kw string) bool {
	return bytes.Equal(line, []byte(kw)) || bytes.HasPrefix(line, []byte(kw+" "))
}

// response reads to the OK or ERR that ends an answer; status and comment
// lines are skipped. Data lines are an error here.
func (l *lineReader) response() ([]byte, error) {
	for {
		line, err := l.readLine()
		if err != nil {
			return nil, err
		}
		switch {
		case isLine(line, "OK"):
			return line, nil
		case isLine(line, "ERR"):
			return nil, parseAssuanErr(line)
		case isLine(line, "S"), len(line) > 0 && line[0] == '#':
		default:
			return nil, errors.New("pinentry: unexpected answer")
		}
	}
}

// getpin reads GETPIN's answer, decoding D lines into *pin.
func (l *lineReader) getpin(pin *[]byte) error {
	for {
		line, err := l.readLine()
		if err != nil {
			return err
		}
		switch {
		case isLine(line, "D"):
			if len(line) < 2 {
				continue
			}
			if err := assuanDecode(pin, line[2:]); err != nil {
				return err
			}
		case isLine(line, "OK"):
			return nil
		case isLine(line, "ERR"):
			return parseAssuanErr(line)
		case isLine(line, "S"), len(line) > 0 && line[0] == '#':
		default:
			// Never echo the line: it may be part of the PIN.
			return errors.New("pinentry: unexpected answer")
		}
	}
}

// assuanDecode appends data with its %XX escapes decoded to *dst, which
// never grows past its capacity.
func assuanDecode(dst *[]byte, data []byte) error {
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c == '%' {
			if i+2 >= len(data) {
				return errors.New("pinentry: malformed escape")
			}
			hi, ok1 := unhex(data[i+1])
			lo, ok2 := unhex(data[i+2])
			if !ok1 || !ok2 {
				return errors.New("pinentry: malformed escape")
			}
			c = hi<<4 | lo
			i += 2
		}
		if len(*dst) == cap(*dst) {
			return errors.New("pinentry: PIN too long")
		}
		*dst = append(*dst, c)
	}
	return nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}
