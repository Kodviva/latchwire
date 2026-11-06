package main

import (
	"context"
	"fmt"
	"runtime"

	"github.com/Kodviva/latchwire/internal/msg"
)

// version and commit are stamped by packaging/build.sh with -X. A plain go
// build keeps these values.
var (
	version = "dev"
	commit  = "unknown"
)

func cmdVersion(_ context.Context, e *env, args []string) error {
	if err := wantArgs("version", args, 0); err != nil {
		return err
	}
	fmt.Fprintf(e.stdout, msg.VersionFmt+"\n", version, commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
	return nil
}
