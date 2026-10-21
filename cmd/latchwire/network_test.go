package main

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/Kodviva/latchwire/internal/ipc"
	"github.com/Kodviva/latchwire/internal/msg"
)

// network prints the current network ID; one that cannot be trusted gets a
// note on stderr.
func TestNetworkCLIPrintsCurrentID(t *testing.T) {
	for id, note := range map[string]bool{netCafe: false, "unknown": true, "none": true} {
		te := newTestEnv(nil)
		rpc := &fakeRPC{replies: map[string]func(any, any) error{
			ipc.MethodNetworkCurrent: func(_, r any) error {
				setResult(t, r, ipc.NetworkCurrent{ID: id})
				return nil
			},
		}}
		withRPC(te, rpc)
		if code := run(context.Background(), te.env, []string{"network"}); code != 0 {
			t.Fatalf("%s: exit %d: %s", id, code, te.errOut)
		}
		if got := strings.Join(rpc.methods(), ","); got != ipc.MethodNetworkCurrent {
			t.Fatalf("%s: calls %s", id, got)
		}
		if out := te.out.String(); out != id+"\n" {
			t.Errorf("%s: output %q", id, out)
		}
		wantNote := fmt.Sprintf(msg.NetworkUntrustableNoteFmt, id)
		if has := strings.Contains(te.errOut.String(), wantNote); has != note {
			t.Errorf("%s: stderr %q, note expected: %v", id, te.errOut, note)
		}
	}
	te := newTestEnv(nil)
	rpc := &fakeRPC{}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"network", "x"}); code != 2 || len(rpc.calls) != 0 {
		t.Fatalf("network x: exit %d, %d calls", code, len(rpc.calls))
	}
}

// --trust-current-network asks the daemon for the current network and adds
// it to the trusted networks; "unknown" and "none" are refused before the
// policy is changed (P10).
func TestPolicyTrustCurrentNetwork(t *testing.T) {
	te := newTestEnv(nil)
	rpc := &fakeRPC{replies: map[string]func(any, any) error{
		ipc.MethodNetworkCurrent: func(_, r any) error {
			setResult(t, r, ipc.NetworkCurrent{ID: netCafe})
			return nil
		},
		ipc.MethodTunnelPolicySet: func(_, r any) error {
			setResult(t, r, ipc.TunnelPolicy{Name: "office", KillSwitch: "auto", TrustedNetworks: []string{netHome, netCafe}})
			return nil
		},
	}}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"policy", "office", "--trust-current-network", "--trust-network", netHome}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if got := strings.Join(rpc.methods(), ","); got != ipc.MethodNetworkCurrent+","+ipc.MethodTunnelPolicySet {
		t.Fatalf("calls %s", got)
	}
	want := ipc.TunnelPolicySet{Name: "office", Trust: []string{netHome, netCafe}}
	if got := rpc.calls[1].params.(ipc.TunnelPolicySet); !reflect.DeepEqual(got, want) {
		t.Errorf("params %+v, want %+v", got, want)
	}

	for _, id := range []string{"unknown", "none"} {
		te := newTestEnv(nil)
		rpc := &fakeRPC{replies: map[string]func(any, any) error{
			ipc.MethodNetworkCurrent: func(_, r any) error {
				setResult(t, r, ipc.NetworkCurrent{ID: id})
				return nil
			},
		}}
		withRPC(te, rpc)
		if code := run(context.Background(), te.env, []string{"policy", "office", "--trust-current-network"}); code != 1 {
			t.Fatalf("%s: exit %d, want 1", id, code)
		}
		if got := strings.Join(rpc.methods(), ","); got != ipc.MethodNetworkCurrent {
			t.Fatalf("%s: calls %s", id, got)
		}
		if want := fmt.Sprintf(msg.PolicyUntrustableNetworkFmt, id); !strings.Contains(te.errOut.String(), want) {
			t.Errorf("%s: stderr %q, want %q", id, te.errOut, want)
		}
	}
}

// --trust-current-network=false changes nothing (the policy is printed);
// the usage and a trust change carry the P22 warning.
func TestPolicyTrustWarningAndFalseFlag(t *testing.T) {
	te := newTestEnv(nil)
	rpc := &fakeRPC{replies: map[string]func(any, any) error{
		ipc.MethodTunnelPolicyGet: func(_, r any) error {
			setResult(t, r, ipc.TunnelPolicy{Name: "office", KillSwitch: "auto"})
			return nil
		},
	}}
	withRPC(te, rpc)
	if code := run(context.Background(), te.env, []string{"policy", "office", "--trust-current-network=false"}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if got := strings.Join(rpc.methods(), ","); got != ipc.MethodTunnelPolicyGet {
		t.Fatalf("calls %s", got)
	}

	if !strings.Contains(msg.CLIUsage, "anyone there can copy") {
		t.Error("usage lacks the trusted-network warning")
	}
	te = newTestEnv(nil)
	withRPC(te, &fakeRPC{})
	if code := run(context.Background(), te.env, []string{"policy", "--help"}); code != 0 {
		t.Fatalf("policy --help: exit %d", code)
	}
	if !strings.Contains(te.out.String(), msg.PolicyTrustWarning) {
		t.Errorf("policy --help: %q lacks the warning", te.out)
	}
	te = newTestEnv(nil)
	withRPC(te, &fakeRPC{replies: map[string]func(any, any) error{
		ipc.MethodTunnelPolicySet: func(_, r any) error {
			setResult(t, r, ipc.TunnelPolicy{Name: "office", KillSwitch: "auto", TrustedNetworks: []string{netHome}})
			return nil
		},
	}})
	if code := run(context.Background(), te.env, []string{"policy", "office", "--trust-network", netHome}); code != 0 {
		t.Fatalf("exit %d: %s", code, te.errOut)
	}
	if !strings.Contains(te.errOut.String(), msg.PolicyTrustWarning) {
		t.Errorf("stderr %q lacks the warning", te.errOut)
	}
}
