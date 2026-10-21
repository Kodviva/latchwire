//go:build darwin || linux

package netcfg

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
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
	writeTool(t, d, "tool", `cat; echo oops >&2; exit 3`)
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
