package ipctest

import (
	"crypto/rand"
	"encoding/hex"
	"testing"
)

func path(t testing.TB) string {
	var b [8]byte
	rand.Read(b[:])
	return `\\.\pipe\latchwire-test-` + hex.EncodeToString(b[:])
}
