//go:build darwin || linux

package netcfg

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeTool(t *testing.T, dir, name, script string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

func TestExecRunnerUsesFixedDirs(t *testing.T) {
	fixed, onPath, empty := t.TempDir(), t.TempDir(), t.TempDir()
	writeTool(t, fixed, "ip", `echo fixed`)
	writeTool(t, onPath, "ip", `echo path`)
	writeTool(t, onPath, "only-on-path", `echo path`)
	t.Setenv("PATH", onPath+":"+os.Getenv("PATH"))

	out, err := execRunner{dirs: []string{empty, fixed}}.Run(ctx, "ip", []string{"a"}, nil)
	if err != nil || strings.TrimSpace(string(out)) != "fixed" {
		t.Fatalf("Run = %q, %v; want the fixed directory's tool", out, err)
	}
	// A tool that exists only on PATH is not found.
	_, err = execRunner{dirs: []string{empty, fixed}}.Run(ctx, "only-on-path", nil, nil)
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("err = %v, want exec.ErrNotFound", err)
	}
	// Names are plain file names, never paths.
	_, err = execRunner{dirs: []string{fixed}}.Run(ctx, "../"+filepath.Base(onPath)+"/ip", nil, nil)
	if !errors.Is(err, exec.ErrNotFound) {
		t.Fatalf("path-like name: err = %v, want exec.ErrNotFound", err)
	}
}

func TestExecRunnerStdinStdoutStderr(t *testing.T) {
	d := t.TempDir()
	writeTool(t, d, "tool", `/bin/cat; echo oops >&2; exit 3`)
	out, err := execRunner{dirs: []string{d}}.Run(ctx, "tool", []string{"secret-free-arg"}, []byte("from-stdin"))
	if string(out) != "from-stdin" {
		t.Errorf("stdout = %q", out)
	}
	if err == nil || !strings.Contains(err.Error(), "oops") {
		t.Errorf("err = %v, want stderr in the error", err)
	}
	if strings.Contains(err.Error(), "from-stdin") {
		t.Errorf("stdin leaked into the error: %v", err)
	}
}

func TestExecRunnerDefaultDirsAreFixed(t *testing.T) {
	r := ExecRunner().(execRunner)
	for _, d := range r.dirs {
		if !filepath.IsAbs(d) {
			t.Errorf("command dir %q is not absolute", d)
		}
	}
	if len(r.dirs) == 0 {
		t.Error("no command dirs")
	}
}

func TestExecRunnerMinimalEnv(t *testing.T) {
	d := t.TempDir()
	writeTool(t, d, "tool", `/usr/bin/env | /usr/bin/sort`)
	t.Setenv("LATCHWIRE_SECRET_TEST", "leak")
	t.Setenv("LANG", "tr_TR.UTF-8")
	out, err := execRunner{dirs: []string{d, "/other"}}.Run(ctx, "tool", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		switch {
		case l == "LC_ALL=C", l == "PATH="+d+":/other":
		case strings.HasPrefix(l, "PWD="), strings.HasPrefix(l, "SHLVL="), strings.HasPrefix(l, "_="), strings.HasPrefix(l, "OLDPWD="):
			// set by the shell itself
		default:
			t.Errorf("unexpected environment entry %q", l)
		}
	}
}

func TestExecRunnerCapsStderr(t *testing.T) {
	d := t.TempDir()
	writeTool(t, d, "tool", `/usr/bin/head -c 100000 /dev/zero | /usr/bin/tr '\0' 'x' >&2; exit 1`)
	_, err := execRunner{dirs: []string{d}}.Run(ctx, "tool", nil, nil)
	if err == nil {
		t.Fatal("want error")
	}
	if n := len(err.Error()); n > maxStderr+256 {
		t.Fatalf("error is %d bytes, want it capped near %d", n, maxStderr)
	}
	if !strings.Contains(err.Error(), "xxxx") {
		t.Fatalf("error lost the stderr text: %.80q", err)
	}
}

// A background child that keeps the output pipes open must not hold Run
// beyond the wait delay.
func TestExecRunnerWaitDelay(t *testing.T) {
	d := t.TempDir()
	writeTool(t, d, "tool", `/bin/sleep 20 &
echo started`)
	start := time.Now()
	execRunner{dirs: []string{d}}.Run(ctx, "tool", nil, nil)
	if el := time.Since(start); el > 10*time.Second {
		t.Fatalf("Run took %v, want it bounded by the wait delay", el)
	}
}
