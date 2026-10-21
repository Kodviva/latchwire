package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

const (
	netHome  = "0123456789abcdef"
	netCafe  = "fedcba9876543210"
	uidAlice = 1001
	uidBob   = 1002
)

func withUsers(te *testEnv) {
	te.lookupUser = func(name string) (uint32, error) {
		switch name {
		case "alice":
			return uidAlice, nil
		case "bob":
			return uidBob, nil
		}
		return 0, errors.New("unknown user " + name)
	}
	te.userName = func(uid uint32) string {
		switch uid {
		case uidAlice:
			return "alice"
		case uidBob:
			return "bob"
		}
		return ""
	}
}

func TestPolicyCLIParsesFlags(t *testing.T) {
	yes, no := true, false
	want := ipc.TunnelPolicySet{Name: "office", KillSwitch: "on", AutoConnect: &yes, OnDemand: &no,
		Trust: []string{netHome}, Untrust: []string{netCafe}, Allow: []uint32{uidAlice}, Deny: []uint32{uidBob}}
	for _, args := range [][]string{
		{"policy", "office", "--kill-switch", "on", "--auto-connect", "--on-demand=false", "--trust-network", netHome,
			"--untrust-network", netCafe, "--allow-user", "alice", "--deny-user", "bob"},
		{"policy", "--kill-switch=on", "--auto-connect=true", "--on-demand=false", "--trust-network=" + netHome,
			"office", "--untrust-network", netCafe, "--allow-user=alice", "--deny-user=bob"},
	} {
		te := newTestEnv(nil)
		withUsers(te)
		rpc := &fakeRPC{replies: map[string]func(any, any) error{
			ipc.MethodTunnelPolicySet: func(_, r any) error {
				setResult(t, r, ipc.TunnelPolicy{Name: "office", KillSwitch: "on", AutoConnect: true,
					TrustedNetworks: []string{netHome}, AllowedUsers: []uint32{uidAlice, 4711}})
				return nil
			},
		}}
		withRPC(te, rpc)
		if code := run(context.Background(), te.env, args); code != 0 {
			t.Fatalf("%v: exit %d: %s", args, code, te.errOut)
		}
		if got := strings.Join(rpc.methods(), ","); got != ipc.MethodTunnelPolicySet {
			t.Fatalf("%v: calls %s", args, got)
		}
		if got := rpc.calls[0].params.(ipc.TunnelPolicySet); !reflect.DeepEqual(got, want) {
			t.Errorf("%v: params %+v, want %+v", args, got, want)
		}
		wantOut := fmt.Sprintf(msg.PolicyPrintFmt+"\n", "office", "on", msg.PolicyOn, msg.PolicyOff, netHome, "alice (1001), 4711")
		if out := te.out.String(); out != wantOut {
			t.Errorf("%v: output\n%s\nwant\n%s", args, out, wantOut)
		}
	}

	// No flags: the policy is read and printed.
	te := newTestEnv(nil)
	withUsers(te)
	rpc := &fakeRPC{replies: map[string]func(any, any) error{
		ipc.MethodTunnelPolicyGet: func(_, r any) error {
			setResult(t, r, ipc.TunnelPolicy{Name: "office", KillSwitch: "auto"})
			return nil
		},
	}}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"policy", "office"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if got := strings.Join(rpc.methods(), ","); got != ipc.MethodTunnelPolicyGet {
		t.Fatalf("calls %s", got)
	}
	if p := rpc.calls[0].params.(ipc.TunnelName); p.Name != "office" {
		t.Errorf("params %+v", p)
	}
	wantOut := fmt.Sprintf(msg.PolicyPrintFmt+"\n", "office", "auto", msg.PolicyOff, msg.PolicyOff, msg.PolicyNone, msg.PolicyAdminsOnly)
	if out := te.out.String(); out != wantOut {
		t.Errorf("output\n%s\nwant\n%s", out, wantOut)
	}

	// A connected tunnel still running with another kill switch setting.
	te = newTestEnv(nil)
	withRPC(te, &fakeRPC{replies: map[string]func(any, any) error{
		ipc.MethodTunnelPolicyGet: func(_, r any) error {
			setResult(t, r, ipc.TunnelPolicy{Name: "office", KillSwitch: "on", KillSwitchInEffect: "auto"})
			return nil
		},
	}})
	if code := run(context.Background(), te.env, []string{"policy", "office"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if note := fmt.Sprintf(msg.PolicyKillSwitchPendingFmt, "office", "auto", "on"); !strings.Contains(te.out.String(), note) {
		t.Errorf("output lacks %q:\n%s", note, te.out)
	}

	// A deny that left the tunnel blocking.
	te = newTestEnv(nil)
	withUsers(te)
	withRPC(te, &fakeRPC{replies: map[string]func(any, any) error{
		ipc.MethodTunnelPolicySet: func(_, r any) error {
			setResult(t, r, ipc.TunnelPolicy{Name: "office", KillSwitch: "on", RevokedBlocking: true})
			return nil
		},
	}})
	if code := run(context.Background(), te.env, []string{"policy", "office", "--deny-user", "bob"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if note := fmt.Sprintf(msg.PolicyRevokedBlockingFmt, "office"); !strings.Contains(te.out.String(), note) {
		t.Errorf("output lacks %q:\n%s", note, te.out)
	}

	// Mistakes never reach the daemon.
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"policy"}, 2},
		{[]string{"policy", "a", "b"}, 2},
		{[]string{"policy", "office", "--kill-switch", "maybe"}, 2},
		{[]string{"policy", "office", "--auto-connect=perhaps"}, 2},
		{[]string{"policy", "office", "--trust-network", "unknown"}, 2},
		{[]string{"policy", "office", "--trust-network", "none"}, 2},
		{[]string{"policy", "office", "--trust-network", "home-wifi"}, 2},
		{[]string{"policy", "office", "--trust-current-network"}, 2},
		{[]string{"policy", "office", "--allow-user", "mallory"}, 2},
		{[]string{"policy", "office", "--deny-user", ""}, 2},
	} {
		te := newTestEnv(nil)
		withUsers(te)
		rpc := &fakeRPC{}
		withRPC(te, rpc)
		if code := run(context.Background(), te.env, tc.args); code != tc.code {
			t.Errorf("%v: exit %d, want %d (%s)", tc.args, code, tc.code, te.errOut)
		}
		if len(rpc.calls) != 0 {
			t.Errorf("%v: called the daemon", tc.args)
		}
	}
}

// add sends the user who ran sudo as the tunnel's owner.
func TestAddSendsSudoUIDAsOwner(t *testing.T) {
	file := filepath.Join(t.TempDir(), "office.conf")
	if err := os.WriteFile(file, []byte("[Interface]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for sudo, want := range map[string]uint32{"501": 501, "": 0, "x": 0, "-1": 0} {
		te := newTestEnv(nil)
		te.getenv = func(k string) string {
			if k == "SUDO_UID" {
				return sudo
			}
			return ""
		}
		rpc := &fakeRPC{}
		withRPC(te, rpc)
		if code := run(context.Background(), te.env, []string{"add", "office", file}); code != 0 {
			t.Fatalf("SUDO_UID=%q: exit %d: %s", sudo, code, te.errOut)
		}
		if p := rpc.calls[0].params.(ipc.TunnelAdd); p.Owner != want {
			t.Errorf("SUDO_UID=%q: owner %d, want %d", sudo, p.Owner, want)
		}
	}
}
