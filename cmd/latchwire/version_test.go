package main

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"testing"
)

func TestVersionCommand(t *testing.T) {
	for _, tc := range []struct{ version, commit string }{
		{"dev", "unknown"}, // a plain go build
		{"1.2.3", "0123456789ab"},
	} {
		oldV, oldC := version, commit
		version, commit = tc.version, tc.commit
		t.Cleanup(func() { version, commit = oldV, oldC })

		var out, errOut bytes.Buffer
		code := run(context.Background(), &env{stdout: &out, stderr: &errOut}, []string{"version"})
		if code != exitOK {
			t.Fatalf("exit %d, stderr %q", code, errOut.String())
		}
		want := fmt.Sprintf("latchwire %s (%s, %s %s/%s)\n", tc.version, tc.commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
		if out.String() != want {
			t.Fatalf("got %q, want %q", out.String(), want)
		}
	}
}

func TestVersionTakesNoArguments(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run(context.Background(), &env{stdout: &out, stderr: &errOut}, []string{"version", "x"}); code != exitUsage {
		t.Fatalf("exit %d, want %d", code, exitUsage)
	}
}
