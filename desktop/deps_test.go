package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The production app links neither the test-only software key nor the demo
// backend. The demo build tag is the only way in.
func TestBinaryLinksNoTestKey(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go list -deps: %v\n%s", err, out)
	}
	for _, pkg := range strings.Fields(string(out)) {
		if strings.HasSuffix(pkg, "/keyprovider/softkey") || strings.HasSuffix(pkg, "/desktop/demo") {
			t.Fatalf("the app links %s", pkg)
		}
	}
}
