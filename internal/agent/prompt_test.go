package agent

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Kodviva/latchwire/internal/keyprovider"
	"github.com/Kodviva/latchwire/internal/msg"
)

var descA = keyprovider.Description{Kind: "piv", Serial: serialA, Slot: 0x82}

// ---- osascript (macOS) ----

type osaCall struct {
	path  string
	args  []string
	stdin []byte
}

// osaRecorder records osascript calls and answers with out/err.
func osaRecorder(calls *[]osaCall, out string, err error) func(ctx context.Context, path string, args []string, stdin []byte) ([]byte, error) {
	return func(ctx context.Context, path string, args []string, stdin []byte) ([]byte, error) {
		*calls = append(*calls, osaCall{path, slices.Clone(args), slices.Clone(stdin)})
		if err != nil {
			return nil, err
		}
		return []byte(out), nil
	}
}

func TestOsascriptPromptNeverPutsPINInArgs(t *testing.T) {
	var calls []osaCall
	// A trailing space belongs to the PIN; only osascript's newline goes.
	p := &osascriptPrompter{run: osaRecorder(&calls, testPIN+" \n", nil), timeout: time.Minute}
	pin, err := p.PIN(descA, 3)
	if err != nil {
		t.Fatal(err)
	}
	if pin != testPIN+" " {
		t.Fatalf("PIN %q, want %q", pin, testPIN+" ")
	}
	if len(calls) != 1 {
		t.Fatalf("%d osascript calls, want 1", len(calls))
	}
	c := calls[0]
	if c.path != "/usr/bin/osascript" {
		t.Fatalf("ran %q, want /usr/bin/osascript", c.path)
	}
	if len(c.args) == 0 || c.args[0] != "-" {
		t.Fatalf("args %q: the script must come from stdin (first argument \"-\")", c.args)
	}
	for _, a := range c.args {
		if strings.Contains(a, testPIN) {
			t.Fatalf("PIN in argument %q", a)
		}
	}
	script := string(c.stdin)
	for _, want := range []string{"on run argv", "display dialog", "with hidden answer", "text returned"} {
		if !strings.Contains(script, want) {
			t.Fatalf("script lacks %q:\n%s", want, script)
		}
	}
	if strings.Contains(script, testPIN) {
		t.Fatal("PIN in the script")
	}
	if want := fmt.Sprintf(msg.AgentPINDialogFmt, serialA, 0x82, 3); c.args[1] != want {
		t.Fatalf("dialog text %q, want %q", c.args[1], want)
	}
}

func TestOsascriptLastRetryInDialog(t *testing.T) {
	var calls []osaCall
	p := &osascriptPrompter{run: osaRecorder(&calls, testPIN+"\n", nil), timeout: time.Minute}
	if _, err := p.PIN(descA, 1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(calls[0].args[1], msg.LastPINRetry) {
		t.Fatalf("dialog text %q lacks the last-retry warning", calls[0].args[1])
	}
}

func TestOsascriptWarnNotifies(t *testing.T) {
	var calls []osaCall
	p := &osascriptPrompter{run: osaRecorder(&calls, "", errors.New("no notification")), timeout: time.Minute}
	p.Warn(msg.LastPINRetry) // a failed notification is only logged
	if len(calls) != 1 || calls[0].path != osascriptPath || calls[0].args[0] != "-" ||
		calls[0].args[1] != msg.LastPINRetry || !strings.Contains(string(calls[0].stdin), "display notification") {
		t.Fatalf("calls %+v", calls)
	}
}

func TestOsascriptCancel(t *testing.T) {
	var calls []osaCall
	cancel := &childError{err: errors.New("exit status 1"), stderr: "0:310: execution error: User canceled. (-128)"}
	p := &osascriptPrompter{run: osaRecorder(&calls, "", cancel), timeout: time.Minute}
	if _, err := p.PIN(descA, 3); !errors.Is(err, keyprovider.ErrPINRequired) {
		t.Fatalf("cancel gave %v, want ErrPINRequired", err)
	}

	other := &childError{err: errors.New("exit status 1"), stderr: "execution error: No user interaction allowed. (-1713)"}
	p = &osascriptPrompter{run: osaRecorder(&calls, "", other), timeout: time.Minute}
	_, err := p.PIN(descA, 3)
	if err == nil || errors.Is(err, keyprovider.ErrPINRequired) {
		t.Fatalf("dialog failure gave %v, want a real error", err)
	}
	if !strings.Contains(err.Error(), "-1713") {
		t.Fatalf("error %q lost osascript's reason", err)
	}
}

func TestOsascriptKilledIsPINRequired(t *testing.T) {
	p := &osascriptPrompter{timeout: -childGrace, // ctx already expired
		run: func(ctx context.Context, _ string, _ []string, _ []byte) ([]byte, error) {
			<-ctx.Done()
			return nil, &childError{err: errors.New("signal: killed")}
		}}
	_, err := p.PIN(descA, 3)
	if !errors.Is(err, keyprovider.ErrPINRequired) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("killed dialog gave %v, want ErrPINRequired (not a context error)", err)
	}
}

func TestOsascriptEmptyOutputIsError(t *testing.T) {
	var calls []osaCall
	p := &osascriptPrompter{run: osaRecorder(&calls, "", nil), timeout: time.Minute}
	if _, err := p.PIN(descA, 3); err == nil {
		t.Fatal("no output accepted as a PIN")
	}
}

// runChild gives the child exactly the environment it is handed, the
// script on stdin, and refuses oversized output.
func TestRunChildEnvAndCaps(t *testing.T) {
	env := helperEnv("echo")
	out, err := runChild(context.Background(), os.Args[0], []string{"-test.run=^TestHelperProcess$"}, []byte("script-on-stdin"), env)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if lines[0] != "stdin=script-on-stdin" {
		t.Fatalf("child read %q", lines[0])
	}
	gotEnv := lines[1:]
	slices.Sort(gotEnv)
	wantEnv := slices.Clone(env)
	slices.Sort(wantEnv)
	if !slices.Equal(gotEnv, wantEnv) {
		t.Fatalf("child env %q, want %q", gotEnv, wantEnv)
	}

	env = helperEnv("flood")
	if _, err := runChild(context.Background(), os.Args[0], []string{"-test.run=^TestHelperProcess$"}, nil, env); err == nil {
		t.Fatal("oversized output accepted")
	}

	env = helperEnv("fail")
	_, err = runChild(context.Background(), os.Args[0], []string{"-test.run=^TestHelperProcess$"}, nil, env)
	var ce *childError
	if !errors.As(err, &ce) || !strings.Contains(ce.stderr, "helper failed") {
		t.Fatalf("failure gave %v, want a childError carrying stderr", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	env = helperEnv("hang")
	start := time.Now()
	if _, err := runChild(ctx, os.Args[0], []string{"-test.run=^TestHelperProcess$"}, nil, env); err == nil {
		t.Fatal("hung child succeeded")
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("hung child took %v to stop", d)
	}
}

// ---- pinentry (Linux) ----

// fakePinentry plays pinentry on the far side of two pipes. reply maps a
// command verb to the lines sent back; verbs not listed get "OK".
type fakePinentry struct {
	cmds  []string
	done  chan struct{}
	cliR  *io.PipeReader
	cliW  *io.PipeWriter
	reply map[string]string
}

func newFakePinentry(t *testing.T, reply map[string]string) *fakePinentry {
	t.Helper()
	srvR, cliW := io.Pipe()
	cliR, srvW := io.Pipe()
	f := &fakePinentry{done: make(chan struct{}), cliR: cliR, cliW: cliW, reply: reply}
	go func() {
		defer close(f.done)
		defer srvW.Close()
		fmt.Fprint(srvW, "OK Pleased to meet you\n")
		sc := bufio.NewScanner(srvR)
		for sc.Scan() {
			line := sc.Text()
			f.cmds = append(f.cmds, line)
			verb, _, _ := strings.Cut(line, " ")
			r, ok := f.reply[verb]
			if !ok {
				r = "OK\n"
			}
			fmt.Fprint(srvW, r)
			if verb == "BYE" {
				return
			}
		}
	}()
	t.Cleanup(func() {
		// Unblock the fake when the client stopped reading early.
		cliW.Close()
		cliR.Close()
		<-f.done
	})
	return f
}

func (f *fakePinentry) finish() []string {
	f.cliW.Close()
	<-f.done
	return f.cmds
}

func TestPinentryAssuanFlow(t *testing.T) {
	f := newFakePinentry(t, map[string]string{
		// Status and comment lines come before the data; %25 is "%".
		"GETPIN": "S PINENTRY_LAUNCHED 1234 gnome3\n# comment\nD 73%2519\nD 05\nOK\n",
	})
	pin, err := pinentryConverse(f.cliR, f.cliW, "Latchwire", "line one\nline two: 100%\r", "PIN", 60)
	if err != nil {
		t.Fatal(err)
	}
	if string(pin) != "73%1905" {
		t.Fatalf("PIN %q, want %q", pin, "73%1905")
	}
	want := []string{
		"SETTITLE Latchwire",
		"SETDESC line one%0Aline two: 100%25%0D",
		"SETPROMPT PIN",
		"SETTIMEOUT 60",
		"GETPIN",
		"BYE",
	}
	if got := f.finish(); !slices.Equal(got, want) {
		t.Fatalf("commands\n%q\nwant\n%q", got, want)
	}
}

func TestPinentryCancel(t *testing.T) {
	f := newFakePinentry(t, map[string]string{"GETPIN": "ERR 83886179 Operation cancelled <Pinentry>\n"})
	pin, err := pinentryConverse(f.cliR, f.cliW, "Latchwire", "desc", "PIN", 60)
	if !errors.Is(err, keyprovider.ErrPINRequired) {
		t.Fatalf("cancel gave %v, want ErrPINRequired", err)
	}
	if len(pin) != 0 {
		t.Fatalf("cancel returned PIN %q", pin)
	}
	// The pinentry timeout is a cancel too.
	f = newFakePinentry(t, map[string]string{"GETPIN": "ERR 83886142 Timeout <Pinentry>\n"})
	if _, err := pinentryConverse(f.cliR, f.cliW, "Latchwire", "desc", "PIN", 60); !errors.Is(err, keyprovider.ErrPINRequired) {
		t.Fatalf("timeout gave %v, want ErrPINRequired", err)
	}
}

func TestPinentryErrors(t *testing.T) {
	for name, reply := range map[string]map[string]string{
		"getpin failure":   {"GETPIN": "ERR 83918950 Inappropriate ioctl for device <Pinentry>\n"},
		"settitle failure": {"SETTITLE": "ERR 83886355 Unknown command\n"},
		"bad escape":       {"GETPIN": "D 12%G1\nOK\n"},
		"unexpected line":  {"GETPIN": "INQUIRE SOMETHING\n"},
		"huge PIN":         {"GETPIN": "D " + strings.Repeat("1", 900) + "\nD " + strings.Repeat("1", 900) + "\nOK\n"},
		"long line":        {"GETPIN": "S " + strings.Repeat("x", 5000) + "\nOK\n"},
	} {
		t.Run(name, func(t *testing.T) {
			f := newFakePinentry(t, reply)
			_, err := pinentryConverse(f.cliR, f.cliW, "Latchwire", "desc", "PIN", 60)
			if err == nil || errors.Is(err, keyprovider.ErrPINRequired) {
				t.Fatalf("got %v, want a real error", err)
			}
		})
	}
	// An old pinentry without SETTIMEOUT still works.
	f := newFakePinentry(t, map[string]string{"SETTIMEOUT": "ERR 536871187 Unknown IPC command\n", "GETPIN": "D 1234\nOK\n"})
	if pin, err := pinentryConverse(f.cliR, f.cliW, "Latchwire", "desc", "PIN", 60); err != nil || string(pin) != "1234" {
		t.Fatalf("got %q, %v", pin, err)
	}
	// A greeting that is not OK.
	srvR, cliW := io.Pipe()
	cliR, srvW := io.Pipe()
	go func() { fmt.Fprint(srvW, "ERR 1 no\n"); srvW.Close(); io.Copy(io.Discard, srvR) }()
	if _, err := pinentryConverse(cliR, cliW, "t", "d", "p", 60); err == nil {
		t.Fatal("bad greeting accepted")
	}
	cliW.Close()
}

func TestFindPinentryFixedDirs(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	mk := func(dir, name string, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	dirs := []string{d1, d2}
	if got := findPinentry(dirs); got != "" {
		t.Fatalf("found %q in empty dirs", got)
	}
	mk(d1, "pinentry-curses", 0o755)
	mk(d2, "pinentry-qt", 0o755)
	mk(d1, "pinentry", 0o644) // not executable
	if err := os.Mkdir(filepath.Join(d2, "pinentry-gnome3"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, want := findPinentry(dirs), filepath.Join(d2, "pinentry-qt"); got != want {
		t.Fatalf("found %q, want %q (names in order, then directories)", got, want)
	}
	mk(d2, "pinentry", 0o755)
	if got, want := findPinentry(dirs), filepath.Join(d2, "pinentry"); got != want {
		t.Fatalf("found %q, want %q", got, want)
	}
	for _, d := range pinentryDirs {
		if !filepath.IsAbs(d) {
			t.Fatalf("pinentry directory %q is not absolute", d)
		}
	}
}

func TestPinentryEnvOnlyDisplayVariables(t *testing.T) {
	host := map[string]string{
		"DISPLAY":                  ":0",
		"WAYLAND_DISPLAY":          "wayland-0",
		"DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus",
		"PATH":                     "/home/u/evil:/usr/bin",
		"LD_PRELOAD":               "/tmp/evil.so",
		"SECRET_TOKEN":             "x",
	}
	env := pinentryEnv(func(k string) string { return host[k] })
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		switch k {
		case "PATH":
			if strings.Contains(v, "evil") {
				t.Fatalf("PATH inherited: %q", kv)
			}
		case "LD_PRELOAD", "SECRET_TOKEN":
			t.Fatalf("%q passed to pinentry", kv)
		}
	}
	for _, want := range []string{"DISPLAY=:0", "WAYLAND_DISPLAY=wayland-0", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus"} {
		if !slices.Contains(env, want) {
			t.Fatalf("env %q lacks %q", env, want)
		}
	}
}

// helperPinentry returns a pinentry prompter whose child is this test
// binary playing pinentry in the given mode.
func helperPinentry(mode string, timeout time.Duration) *pinentryPrompter {
	return &pinentryPrompter{
		find: func() string { return "/fake/pinentry" },
		command: func(ctx context.Context, path string) *exec.Cmd {
			c := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestHelperProcess$")
			c.Env = helperEnv(mode)
			return c
		},
		timeout: timeout,
		grace:   100 * time.Millisecond,
	}
}

func TestPinentryProcess(t *testing.T) {
	pin, err := helperPinentry("pinentry-ok", time.Minute).PIN(descA, 3)
	if err != nil || pin != testPIN {
		t.Fatalf("got %q, %v", pin, err)
	}
	if _, err := helperPinentry("pinentry-cancel", time.Minute).PIN(descA, 3); !errors.Is(err, keyprovider.ErrPINRequired) {
		t.Fatalf("cancel gave %v", err)
	}
	// A pinentry that never answers is killed when the timeout passes.
	start := time.Now()
	_, err = helperPinentry("pinentry-hang", 300*time.Millisecond).PIN(descA, 3)
	if !errors.Is(err, keyprovider.ErrPINRequired) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("hung pinentry gave %v, want ErrPINRequired (not a context error)", err)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("hung pinentry took %v to stop", d)
	}
	// A pinentry that dies mid-conversation is an error.
	if _, err := helperPinentry("pinentry-die", time.Minute).PIN(descA, 3); err == nil || errors.Is(err, keyprovider.ErrPINRequired) {
		t.Fatalf("dead pinentry gave %v", err)
	}
}

func TestNoPinentryIsPINRequired(t *testing.T) {
	p := &pinentryPrompter{find: func() string { return "" }, timeout: time.Minute,
		command: func(context.Context, string) *exec.Cmd { t.Fatal("ran a pinentry that was not found"); return nil }}
	_, err := p.PIN(descA, 3)
	if !errors.Is(err, keyprovider.ErrPINRequired) || !strings.Contains(err.Error(), msg.AgentNoPinentry) {
		t.Fatalf("got %v, want ErrPINRequired with %q", err, msg.AgentNoPinentry)
	}
	var np noPrompter
	np.reason = msg.AgentNoPINDialog
	if _, err := np.PIN(descA, 3); !errors.Is(err, keyprovider.ErrPINRequired) {
		t.Fatalf("no dialog gave %v", err)
	}
}

// ---- selection ----

func TestNewPrompterPrefersTTY(t *testing.T) {
	guiCalled := false
	gui := func() Prompter { guiCalled = true; return noPrompter{reason: "gui"} }
	if p := choosePrompter(func() bool { return true }, gui); p != NewTTYPrompter() || guiCalled {
		t.Fatalf("with a terminal got %T (gui called %v), want the TTY prompter", p, guiCalled)
	}
	if p := choosePrompter(func() bool { return false }, gui); p != (noPrompter{reason: "gui"}) {
		t.Fatalf("without a terminal got %#v, want the dialog prompter", p)
	}
	if NewPrompter() == nil {
		t.Fatal("NewPrompter returned nil")
	}
}

// TestHelperProcess is the child process of the tests above; it does
// nothing in a normal test run.
func TestHelperProcess(t *testing.T) {
	mode := os.Getenv("LATCHWIRE_TEST_HELPER")
	if mode == "" {
		return
	}
	defer os.Exit(0)
	switch mode {
	case "echo":
		in, _ := io.ReadAll(os.Stdin)
		fmt.Printf("stdin=%s\n", in)
		for _, kv := range os.Environ() {
			fmt.Println(kv)
		}
	case "flood":
		fmt.Print(strings.Repeat("x", 64<<10))
	case "fail":
		fmt.Fprintln(os.Stderr, "helper failed")
		os.Exit(1)
	case "hang":
		time.Sleep(time.Minute)
	case "pinentry-ok", "pinentry-cancel", "pinentry-hang", "pinentry-die":
		fmt.Print("OK Pleased to meet you\n")
		sc := bufio.NewScanner(os.Stdin)
		for sc.Scan() {
			verb, _, _ := strings.Cut(sc.Text(), " ")
			switch {
			case verb == "GETPIN" && mode == "pinentry-ok":
				fmt.Print("D " + testPIN + "\nOK\n")
			case verb == "GETPIN" && mode == "pinentry-cancel":
				fmt.Print("ERR 83886179 Operation cancelled <Pinentry>\n")
			case verb == "GETPIN" && mode == "pinentry-hang":
				time.Sleep(time.Minute)
			case verb == "GETPIN" && mode == "pinentry-die":
				os.Exit(2)
			case verb == "BYE":
				fmt.Print("OK closing connection\n")
				return
			default:
				fmt.Print("OK\n")
			}
		}
	}
}

// helperEnv is the environment of a TestHelperProcess child: the osascript
// environment plus the mode. A race-enabled child that exits with status 0
// otherwise sleeps a second at exit.
func helperEnv(mode string) []string {
	return append(slices.Clone(osascriptEnv), "GORACE=atexit_sleep_ms=0", "LATCHWIRE_TEST_HELPER="+mode)
}
