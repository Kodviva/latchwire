package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The test-only software key must never end up in the shipped binary.
func TestBinaryDoesNotLinkSoftkey(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if strings.HasSuffix(pkg, "/keyprovider/softkey") {
			t.Fatalf("cmd/latchwire links %s", pkg)
		}
	}
}
