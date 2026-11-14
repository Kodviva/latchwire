package main

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/msg"
)

func TestMCPCommand(t *testing.T) {
	ran := false
	e := &env{stdout: &bytes.Buffer{}, stderr: &bytes.Buffer{}, runMCP: func(context.Context) error {
		ran = true
		return context.Canceled
	}}
	if code := run(context.Background(), e, []string{"mcp"}); code != exitOK || !ran {
		t.Fatalf("mcp: exit %d, ran %v", code, ran)
	}
	if code := run(context.Background(), e, []string{"mcp", "x"}); code != exitUsage {
		t.Fatalf("mcp x: exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(msg.CLIUsage, "\n  mcp ") {
		t.Error("the usage text lacks the mcp command")
	}
}
