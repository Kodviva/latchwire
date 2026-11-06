package daemon

import (
	"context"
	"errors"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Kodviva/latchwire/internal/ipc"
)

const testSID = "S-1-5-21-1004336348-1177238915-682003330-1001"

func TestAddOwner(t *testing.T) {
	for _, c := range []struct{ named, elevated, want uint32 }{
		{501, 0, 501},    // sudo on Unix
		{0, 0, 0},        // a root shell without sudo
		{0, 1000, 1000},  // an elevated Windows prompt
		{501, 1000, 501}, // what the CLI names wins
	} {
		if got := addOwner(c.named, c.elevated); got != c.want {
			t.Errorf("addOwner(%d, %d) = %d", c.named, c.elevated, got)
		}
	}
}

func TestUserMethodsAbsentOnUnix(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows has the table")
	}
	e := newEnv(t, envOpts{})
	var ie *ipc.Error
	err := e.cli.Call(context.Background(), ipc.MethodUserID, ipc.UserInfo{SID: testSID}, nil)
	if !errors.As(err, &ie) || ie.Code != ipc.CodeNotFound {
		t.Fatalf("%v", err)
	}
}

func usersEnv(t *testing.T, o envOpts) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "users.json")
	o.hook = func(m *Manager) { m.users = ipc.OpenUserTable(path) }
	return newEnv(t, o)
}

func TestUserMethods(t *testing.T) {
	e := usersEnv(t, envOpts{})
	c := e.cli
	var got ipc.UserInfo
	if err := c.Call(context.Background(), ipc.MethodUserID, ipc.UserInfo{SID: testSID}, &got); err != nil {
		t.Fatal(err)
	}
	if got.UID < 1000 || got.SID != testSID {
		t.Fatalf("%+v", got)
	}
	var back ipc.UserInfo
	if err := c.Call(context.Background(), ipc.MethodUserSID, ipc.UserInfo{UID: got.UID}, &back); err != nil {
		t.Fatal(err)
	}
	if back.SID != testSID {
		t.Fatalf("%+v", back)
	}
	if err := c.Call(context.Background(), ipc.MethodUserSID, ipc.UserInfo{UID: 77}, &back); err == nil {
		t.Fatal("found a user that does not exist")
	}
	if err := c.Call(context.Background(), ipc.MethodUserID, ipc.UserInfo{SID: "not a sid"}, &back); err == nil {
		t.Fatal("accepted a bad SID")
	}
}

func TestUserIDIsForAdministrators(t *testing.T) {
	e := usersEnv(t, envOpts{notAdmin: true})
	var ie *ipc.Error
	err := e.cli.Call(context.Background(), ipc.MethodUserID, ipc.UserInfo{SID: testSID}, nil)
	if !errors.As(err, &ie) || ie.Code != ipc.CodeForbidden {
		t.Fatalf("%v", err)
	}
}
