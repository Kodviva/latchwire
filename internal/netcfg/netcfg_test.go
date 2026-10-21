package netcfg

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// recorder records commands instead of running them. failOn makes the
// command whose rendering starts with it fail; missing makes it fail as a
// command that is not installed. out maps a rendered command to its
// output, stdin collects what each command read. onRun, if set, sees every
// command before it is recorded.
type recorder struct {
	cmds    []string
	failOn  string
	missing string
	failErr error // returned by failOn; default "exit status 1"
	out     map[string]string
	stdin   map[string]string
	onRun   func(cmd string)
}

func (r *recorder) Run(_ context.Context, name string, args []string, in []byte) ([]byte, error) {
	c := strings.Join(append([]string{name}, args...), " ")
	if r.onRun != nil {
		r.onRun(c)
	}
	r.cmds = append(r.cmds, c)
	if len(in) > 0 {
		if r.stdin == nil {
			r.stdin = map[string]string{}
		}
		r.stdin[c] = string(in)
	}
	if r.missing != "" && strings.HasPrefix(c, r.missing) {
		return nil, fmt.Errorf("%s: %w", name, exec.ErrNotFound)
	}
	if r.failOn != "" && strings.HasPrefix(c, r.failOn) {
		if r.failErr != nil {
			return nil, r.failErr
		}
		return nil, errors.New("exit status 1")
	}
	return []byte(r.out[c]), nil
}

func pfx(s ...string) []netip.Prefix {
	var out []netip.Prefix
	for _, v := range s {
		out = append(out, netip.MustParsePrefix(v))
	}
	return out
}

func plan(iface string, addrs, routes []netip.Prefix) Plan {
	return Plan{Iface: iface, Addresses: addrs, Routes: routes}
}

func newJournal(t *testing.T) (*Journal, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "run", "journal.json")
	j, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	return j, path
}

type factory func(Runner, *Journal) Configurer

var platforms = map[string]factory{"darwin": newDarwin, "linux": newLinux}

var ctx = context.Background()

func TestDarwinApplyCommands(t *testing.T) {
	r := &recorder{}
	c := newDarwin(r, nil)
	if _, err := c.Apply(ctx, plan("utun7", pfx("10.0.0.2/32"), pfx("10.0.0.0/24"))); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ifconfig utun7 inet 10.0.0.2 10.0.0.2 alias",
		"route -q -n add -inet 10.0.0.0/24 -interface utun7",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
}

func TestDarwinApplyIPv6AndRemove(t *testing.T) {
	r := &recorder{}
	c := newDarwin(r, nil)
	if _, err := c.Apply(ctx, plan("utun3", pfx("fd00::2/128"), pfx("fd00::/64", "10.0.0.1/32"))); err != nil {
		t.Fatal(err)
	}
	r.cmds = nil
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	// Everything Apply did is undone in reverse order.
	want := []string{
		"route -q -n delete -inet 10.0.0.1/32 -interface utun3",
		"route -q -n delete -inet6 fd00::/64 -interface utun3",
		"ifconfig utun3 inet6 fd00::2 -alias",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("remove commands:\n%q\nwant:\n%q", r.cmds, want)
	}
	r.cmds = nil
	if err := c.Remove(ctx); err != nil || len(r.cmds) != 0 {
		t.Fatalf("second Remove: err=%v cmds=%q, want no-op", err, r.cmds)
	}
}

func TestLinuxApplyCommands(t *testing.T) {
	r := &recorder{}
	c := newLinux(r, nil)
	if _, err := c.Apply(ctx, plan("X", pfx("10.0.0.2/32"), pfx("10.0.0.0/24"))); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip address add 10.0.0.2/32 dev X",
		"ip link set X up",
		"ip route add 10.0.0.0/24 dev X",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
	r.cmds = nil
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	want = []string{"ip route del 10.0.0.0/24 dev X", "ip address del 10.0.0.2/32 dev X"}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("remove commands:\n%q\nwant:\n%q", r.cmds, want)
	}
}

// An address with a shorter prefix already brings its connected route; adding
// it again would fail with "File exists".
func TestLinuxSkipsConnectedRoute(t *testing.T) {
	r := &recorder{}
	c := newLinux(r, nil)
	if _, err := c.Apply(ctx, plan("X", pfx("10.0.0.2/24"), pfx("10.0.0.0/24", "10.1.0.0/16"))); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip address add 10.0.0.2/24 dev X",
		"ip link set X up",
		"ip route add 10.1.0.0/16 dev X",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
}

// macOS still refuses a full tunnel (until Task 5); Linux supports it (see
// TestFullTunnelNoLongerRejected).
func TestFullTunnelRejected(t *testing.T) {
	for _, full := range []string{"0.0.0.0/0", "::/0"} {
		r := &recorder{}
		j, _ := newJournal(t)
		_, err := newDarwin(r, j).Apply(ctx, plan("X", pfx("10.0.0.2/32"), pfx("10.0.0.0/24", full)))
		if !errors.Is(err, ErrFullTunnelUnsupported) {
			t.Errorf("darwin %s: err = %v, want ErrFullTunnelUnsupported", full, err)
		}
		if len(r.cmds) != 0 || len(j.Entries()) != 0 {
			t.Errorf("darwin %s: commands ran %q or journal written %v", full, r.cmds, j.Entries())
		}
	}
}

// A failing command rolls back what was already applied and is reported.
func TestApplyFailureRollsBack(t *testing.T) {
	r := &recorder{failOn: "ip route add 10.1.0.0/16"}
	c := newLinux(r, nil)
	_, err := c.Apply(ctx, plan("X", pfx("10.0.0.2/32"), pfx("10.0.0.0/24", "10.1.0.0/16")))
	if err == nil {
		t.Fatal("Apply succeeded, want error")
	}
	if !strings.Contains(err.Error(), "ip route add 10.1.0.0/16 dev X") {
		t.Errorf("error %q does not name the failing command", err)
	}
	want := []string{
		"ip address add 10.0.0.2/32 dev X",
		"ip link set X up",
		"ip route add 10.0.0.0/24 dev X",
		"ip route add 10.1.0.0/16 dev X",
		"ip route del 10.0.0.0/24 dev X",
		"ip address del 10.0.0.2/32 dev X",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
}

func TestNewPicksPlatform(t *testing.T) {
	if New(&recorder{}, nil) == nil {
		t.Fatal("New returned nil")
	}
}

// Apply must reach the journal before the first command runs, so a crash in
// the middle leaves the undo steps behind.
func TestApplyRecordsUndoBeforeRunning(t *testing.T) {
	for name, f := range platforms {
		j, path := newJournal(t)
		var atFirst map[string][]Step
		first := true
		r := &recorder{onRun: func(string) {
			if first {
				first = false
				// A fresh Journal from disk: what a crash would leave.
				j2, err := OpenJournal(path)
				if err != nil {
					t.Errorf("%s: reopening journal: %v", name, err)
					return
				}
				atFirst = j2.Entries()
			}
		}}
		if _, err := f(r, j).Apply(ctx, plan("X", pfx("10.0.0.2/32"), pfx("10.0.0.0/24"))); err != nil {
			t.Fatal(err)
		}
		if len(atFirst["X"]) == 0 {
			t.Errorf("%s: journal empty when the first command ran: %v", name, atFirst)
		}
		// After the whole Apply the journal holds every undo step, in
		// apply order.
		var got []string
		for _, s := range j.Entries()["X"] {
			got = append(got, s.String())
		}
		var want []string
		if name == "darwin" {
			want = []string{
				"ifconfig X inet 10.0.0.2 -alias",
				"route -q -n delete -inet 10.0.0.0/24 -interface X",
			}
		} else {
			want = []string{
				"ip address del 10.0.0.2/32 dev X",
				"ip route del 10.0.0.0/24 dev X",
			}
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: journal steps:\n%q\nwant:\n%q", name, got, want)
		}
	}
}

func TestApplyRollsBackOnFailureAndForgets(t *testing.T) {
	j, _ := newJournal(t)
	r := &recorder{failOn: "ip route add"}
	c := newLinux(r, j)
	if _, err := c.Apply(ctx, plan("X", pfx("10.0.0.2/32"), pfx("10.0.0.0/24"))); err == nil {
		t.Fatal("Apply succeeded, want error")
	}
	// The third command (route add) failed; the first (address add) is
	// undone, the second (link up) has nothing to undo.
	want := []string{
		"ip address add 10.0.0.2/32 dev X",
		"ip link set X up",
		"ip route add 10.0.0.0/24 dev X",
		"ip address del 10.0.0.2/32 dev X",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
	if e := j.Entries(); len(e) != 0 {
		t.Fatalf("journal after rollback: %v, want empty", e)
	}
}

func TestRemoveForgetsOwner(t *testing.T) {
	j, _ := newJournal(t)
	c := newLinux(&recorder{}, j)
	if _, err := c.Apply(ctx, plan("X", pfx("10.0.0.2/32"), pfx("10.0.0.0/24"))); err != nil {
		t.Fatal(err)
	}
	if len(j.Entries()["X"]) == 0 {
		t.Fatal("journal empty after Apply")
	}
	if err := c.Remove(ctx); err != nil {
		t.Fatal(err)
	}
	if e := j.Entries(); len(e) != 0 {
		t.Fatalf("journal after Remove: %v, want empty", e)
	}
}

// A cancelled context must not stop the rollback of a failed Apply.
func TestRollbackSurvivesCancelledContext(t *testing.T) {
	c, cancel := context.WithCancel(ctx)
	r := &ctxRecorder{}
	r.failOn = "ip route add"
	r.onRun = func(string) { cancel() }
	if _, err := newLinux(r, nil).Apply(c, plan("X", pfx("10.0.0.2/32"), pfx("10.0.0.0/24"))); err == nil {
		t.Fatal("Apply succeeded, want error")
	}
	if r.undoCtxErr != nil {
		t.Fatalf("rollback ran with a cancelled context: %v", r.undoCtxErr)
	}
	if len(r.cmds) == 0 || r.cmds[len(r.cmds)-1] != "ip address del 10.0.0.2/32 dev X" {
		t.Fatalf("rollback did not run: %q", r.cmds)
	}
}

type ctxRecorder struct {
	recorder
	undoCtxErr error
}

func (r *ctxRecorder) Run(c context.Context, name string, args []string, stdin []byte) ([]byte, error) {
	if name == "ip" && len(args) > 1 && args[1] == "del" && c.Err() != nil {
		r.undoCtxErr = c.Err()
	}
	return r.recorder.Run(c, name, args, stdin)
}

func TestCleanupRemovesOrphans(t *testing.T) {
	j, path := newJournal(t)
	if err := j.Record("office", []Step{
		{Name: "ip", Args: []string{"address", "del", "10.0.0.2/32", "dev", "office"}},
		{Name: "ip", Args: []string{"route", "del", "10.0.0.0/24", "dev", "office"}},
	}); err != nil {
		t.Fatal(err)
	}
	// A new process: open the journal from disk.
	j2, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	r := &recorder{}
	if err := Cleanup(ctx, r, j2, func(string) bool { return false }); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ip route del 10.0.0.0/24 dev office",
		"ip address del 10.0.0.2/32 dev office",
	}
	if !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands:\n%q\nwant:\n%q", r.cmds, want)
	}
	if e := j2.Entries(); len(e) != 0 {
		t.Fatalf("journal after Cleanup: %v", e)
	}
	j3, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if e := j3.Entries(); len(e) != 0 {
		t.Fatalf("journal file after Cleanup: %v", e)
	}
}

// keep nil claims nothing, and one failing step does not stop the rest nor
// keep the record.
func TestCleanupNilKeepAndFailingStep(t *testing.T) {
	j, _ := newJournal(t)
	j.Record("a", []Step{{Name: "ip", Args: []string{"one"}}, {Name: "ip", Args: []string{"two"}}})
	r := &recorder{failOn: "ip two"}
	err := Cleanup(ctx, r, j, nil)
	if err == nil {
		t.Fatal("Cleanup error = nil, want the failing step reported")
	}
	if want := []string{"ip two", "ip one"}; !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands %q, want %q", r.cmds, want)
	}
	if e := j.Entries(); len(e) != 0 {
		t.Fatalf("journal after Cleanup: %v", e)
	}
}

func TestCleanupKeepsWhenAsked(t *testing.T) {
	j, path := newJournal(t)
	steps := []Step{{Name: "ip", Args: []string{"link", "del", "office"}}}
	j.Record("office", steps)
	j.Record("home", []Step{{Name: "ip", Args: []string{"link", "del", "home"}}})
	r := &recorder{}
	if err := Cleanup(ctx, r, j, func(o string) bool { return o == "office" }); err != nil {
		t.Fatal(err)
	}
	if want := []string{"ip link del home"}; !reflect.DeepEqual(r.cmds, want) {
		t.Fatalf("commands %q, want %q", r.cmds, want)
	}
	j2, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	e := j2.Entries()
	if len(e) != 1 || !reflect.DeepEqual(e["office"], steps) {
		t.Fatalf("journal = %v, want only office untouched", e)
	}
}

func TestJournalFileMode(t *testing.T) {
	j, path := newJournal(t)
	if err := j.Record("a", []Step{{Name: "ip", Args: []string{"x"}, Stdin: []byte("in")}}); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("journal mode %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("journal dir mode %v, want 0700", di.Mode().Perm())
	}
	// Atomic write: the temporary file was renamed away, nothing is left.
	ents, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 || ents[0].Name() != "journal.json" {
		t.Errorf("journal dir entries %v, want only journal.json", ents)
	}
	// Rewrites keep the mode and round-trip stdin.
	if err := j.Record("b", nil); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Stat(path); fi.Mode().Perm() != 0o600 {
		t.Errorf("rewritten journal mode %v, want 0600", fi.Mode().Perm())
	}
	j2, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := j2.Entries()["a"]; len(got) != 1 || string(got[0].Stdin) != "in" {
		t.Errorf("reloaded steps %v", got)
	}
}

// Undo commands fail once the device is closed (the interface is gone); the
// owner's record must go anyway, or the next start would replay them, maybe
// against another VPN's reused utunN.
func TestRemoveForgetsOwnerWhenUndoFails(t *testing.T) {
	for name, f := range platforms {
		j, path := newJournal(t)
		r := &recorder{}
		c := f(r, j)
		if _, err := c.Apply(ctx, plan("X", pfx("10.0.0.2/32"), pfx("10.0.0.0/24"))); err != nil {
			t.Fatal(err)
		}
		r.failOn = map[string]string{"darwin": "ifconfig", "linux": "ip "}[name]
		if err := c.Remove(ctx); err == nil {
			t.Errorf("%s: Remove error = nil, want the undo failure reported", name)
		}
		if e := j.Entries(); len(e) != 0 {
			t.Errorf("%s: journal after Remove: %v, want empty", name, e)
		}
		j2, err := OpenJournal(path)
		if err != nil {
			t.Fatal(err)
		}
		if e := j2.Entries(); len(e) != 0 {
			t.Errorf("%s: journal file after Remove: %v, want empty", name, e)
		}
	}
}

func writeJournalFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "journal.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func asideFiles(t *testing.T, path string) []string {
	t.Helper()
	m, err := filepath.Glob(path + ".corrupt-*")
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// A journal that cannot be parsed, or has another version, is moved aside and
// the journal starts empty: the daemon must still start.
func TestOpenJournalCorruptRecovers(t *testing.T) {
	for name, content := range map[string]string{
		"garbage":       "{nope",
		"empty":         "",
		"wrong version": `{"version":99,"owners":{"x":[{"name":"ip"}]}}`,
		"no version":    `{"owners":{}}`,
	} {
		path := writeJournalFile(t, content)
		j, err := OpenJournal(path)
		if err != nil {
			t.Errorf("%s: OpenJournal: %v, want recovery", name, err)
			continue
		}
		if !j.RecoveredFromCorruption() {
			t.Errorf("%s: RecoveredFromCorruption = false", name)
		}
		if e := j.Entries(); len(e) != 0 {
			t.Errorf("%s: entries %v, want empty", name, e)
		}
		aside := asideFiles(t, path)
		if len(aside) != 1 {
			t.Errorf("%s: aside files %v, want one", name, aside)
			continue
		}
		if b, _ := os.ReadFile(aside[0]); string(b) != content {
			t.Errorf("%s: aside content %q, want the original %q", name, b, content)
		}
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("%s: corrupt file still at the journal path (%v)", name, err)
		}
		// The recovered journal works.
		if err := j.Record("a", []Step{{Name: "ip"}}); err != nil {
			t.Errorf("%s: Record after recovery: %v", name, err)
		}
	}
}

func TestOpenJournalHealthyNotRecovered(t *testing.T) {
	j, path := newJournal(t)
	j.Record("a", []Step{{Name: "ip"}})
	j2, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if j2.RecoveredFromCorruption() || len(asideFiles(t, path)) != 0 {
		t.Fatal("healthy journal reported as recovered")
	}
	if j3, _ := OpenJournal(filepath.Join(t.TempDir(), "none.json")); j3.RecoveredFromCorruption() {
		t.Fatal("missing journal reported as recovered")
	}
}

// A plain read error is not corruption: it fails.
func TestOpenJournalReadErrorFails(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads any file")
	}
	path := writeJournalFile(t, `{"version":1,"owners":{}}`)
	if err := os.Chmod(path, 0); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournal(path); err == nil {
		t.Fatal("OpenJournal succeeded on an unreadable file")
	}
	if len(asideFiles(t, path)) != 0 {
		t.Fatal("unreadable file was moved aside")
	}
	// A directory where the file should be is a read error too.
	dirPath := filepath.Join(t.TempDir(), "journal.json")
	os.Mkdir(dirPath, 0o700)
	if _, err := OpenJournal(dirPath); err == nil {
		t.Fatal("OpenJournal succeeded on a directory")
	}
}

// Running as root, a journal directory or file that others can write, or that
// root does not own, is refused. (geteuid and trustedUID are faked so the
// test needs no root.)
func TestOpenJournalRejectsUntrusted(t *testing.T) {
	oldEuid, oldUID := geteuid, trustedUID
	t.Cleanup(func() { geteuid, trustedUID = oldEuid, oldUID })
	geteuid = func() int { return 0 }
	trustedUID = uint32(os.Getuid()) // the test's files count as root's

	mk := func() (dir, path string) {
		dir = t.TempDir()
		path = filepath.Join(dir, "journal.json")
		if err := os.WriteFile(path, []byte(`{"version":1,"owners":{}}`), 0o600); err != nil {
			t.Fatal(err)
		}
		return
	}
	// Baseline: trusted.
	_, path := mk()
	if _, err := OpenJournal(path); err != nil {
		t.Fatalf("trusted journal refused: %v", err)
	}
	for _, mode := range []os.FileMode{0o666, 0o620, 0o602} {
		_, path := mk()
		os.Chmod(path, mode)
		if _, err := OpenJournal(path); err == nil {
			t.Errorf("file mode %v accepted", mode)
		}
	}
	for _, mode := range []os.FileMode{0o777, 0o770, 0o707} {
		dir, path := mk()
		os.Chmod(dir, mode)
		_, err := OpenJournal(path)
		os.Chmod(dir, 0o700)
		if err == nil {
			t.Errorf("dir mode %v accepted", mode)
		}
	}
	// A missing file in a trusted directory is fine.
	if _, err := OpenJournal(filepath.Join(t.TempDir(), "run", "j.json")); err != nil {
		t.Errorf("missing journal refused: %v", err)
	}
	// Not owned by root.
	trustedUID = uint32(os.Getuid()) + 1
	_, path = mk()
	if _, err := OpenJournal(path); err == nil {
		t.Error("journal owned by another uid accepted")
	}
	// Refusal is not recovery: the file stays where it is.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("refused journal was moved: %v", err)
	}
	// Not root: no checks.
	geteuid = func() int { return 1000 }
	if _, err := OpenJournal(path); err != nil {
		t.Errorf("non-root open refused: %v", err)
	}
}

// When ctx ends mid-cleanup nothing is forgotten: the failures of a cancelled
// run say nothing about the system, and the next start must retry.
func TestCleanupCancelledForgetsNothing(t *testing.T) {
	j, path := newJournal(t)
	j.Record("a", []Step{{Name: "ip", Args: []string{"a1"}}, {Name: "ip", Args: []string{"a2"}}})
	j.Record("b", []Step{{Name: "ip", Args: []string{"b1"}}})
	c, cancel := context.WithCancel(ctx)
	r := &recorder{onRun: func(string) { cancel() }}
	err := Cleanup(c, r, j, nil)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Cleanup error = %v, want context.Canceled", err)
	}
	if len(r.cmds) != 1 {
		t.Errorf("commands after cancel: %q, want only the first", r.cmds)
	}
	j2, err := OpenJournal(path)
	if err != nil {
		t.Fatal(err)
	}
	if e := j2.Entries(); len(e) != 2 {
		t.Fatalf("journal after cancelled Cleanup: %v, want both owners kept", e)
	}
	// Already cancelled before the start: no command at all.
	r = &recorder{}
	if err := Cleanup(c, r, j, nil); err == nil || len(r.cmds) != 0 {
		t.Fatalf("pre-cancelled Cleanup: err=%v cmds=%q", err, r.cmds)
	}
	if len(j.Entries()) != 2 {
		t.Fatal("pre-cancelled Cleanup forgot owners")
	}
}

func TestPlanDarwinAndLinuxUnchanged(t *testing.T) {
	p := plan("utun9", pfx("10.0.0.2/24", "fd00::2/128"), pfx("10.0.0.0/24", "10.1.0.5/16", "fd00::/64"))
	render := func(ss []step) (do, undo []string) {
		for _, s := range ss {
			do = append(do, s.do.String())
			if s.undo != nil {
				undo = append(undo, s.undo.String())
			}
		}
		return
	}
	do, undo := render(planDarwin(p))
	wantDo := []string{
		"ifconfig utun9 inet 10.0.0.2 10.0.0.2 alias",
		"ifconfig utun9 inet6 fd00::2 prefixlen 128 alias",
		"route -q -n add -inet 10.0.0.0/24 -interface utun9",
		"route -q -n add -inet 10.1.0.0/16 -interface utun9",
		"route -q -n add -inet6 fd00::/64 -interface utun9",
	}
	wantUndo := []string{
		"ifconfig utun9 inet 10.0.0.2 -alias",
		"ifconfig utun9 inet6 fd00::2 -alias",
		"route -q -n delete -inet 10.0.0.0/24 -interface utun9",
		"route -q -n delete -inet 10.1.0.0/16 -interface utun9",
		"route -q -n delete -inet6 fd00::/64 -interface utun9",
	}
	if !reflect.DeepEqual(do, wantDo) || !reflect.DeepEqual(undo, wantUndo) {
		t.Errorf("darwin:\ndo   %q\nundo %q", do, undo)
	}
	do, undo = render(planLinux(p))
	wantDo = []string{
		"ip address add 10.0.0.2/24 dev utun9",
		"ip address add fd00::2/128 dev utun9",
		"ip link set utun9 up",
		"ip route add 10.1.0.0/16 dev utun9",
		"ip route add fd00::/64 dev utun9",
	}
	wantUndo = []string{
		"ip address del 10.0.0.2/24 dev utun9",
		"ip address del fd00::2/128 dev utun9",
		"ip route del 10.1.0.0/16 dev utun9",
		"ip route del fd00::/64 dev utun9",
	}
	if !reflect.DeepEqual(do, wantDo) || !reflect.DeepEqual(undo, wantUndo) {
		t.Errorf("linux:\ndo   %q\nundo %q", do, undo)
	}
}

func TestRefreshIsNoOp(t *testing.T) {
	r := &recorder{}
	if err := newLinux(r, nil).Refresh(ctx); err != nil || len(r.cmds) != 0 {
		t.Fatalf("Refresh: err=%v cmds=%q", err, r.cmds)
	}
}
